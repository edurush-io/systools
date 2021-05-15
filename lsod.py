#!/usr/bin/env python3

import os
import argparse
import concurrent.futures

"""
compare speed to
lsof -n | awk '{ print $2 " " $1; }' | sort -rn | uniq -c | sort -rn | head -20
"""

# variables
pid_list = [] # list only, to be used in concurrent execution
pid_score = {} # pid -> count of all FDs, to be used for sorting top FD consumers
pid_stats = {} # to keep all the counters for each FD type
pid_extra = {} # to keep extra info, like command (comm), parent pid (ppid), etc
pid_threads = {} # to keep thread specific stats if requested

totals = { # grand totals for all types with counters
    'socket' : 0,
    'anon_inode' : 0,
    'pipe' : 0,
    'dev' : 0,
    'sys' : 0,
    'run' : 0,
    'proc' : 0,
    'file' : 0 ,
    'unknown' : 0
}
cfg = {} # configuration used in the script
cfg['max_workers'] = 300 # how many threads to use concurrently
cfg['max_pids'] = 10 # how many pids to show
cfg['show_threads'] = False
cfg['max_threads'] = 5
cfg['include_self'] = False
# end variables

### functions

def parse_args ():
    parser = argparse.ArgumentParser (
        description = "Very fast file descriptor usage report",
        usage = "%(prog)s"
    )
    parser.add_argument ("--max_pids", type=int, help="Max num of pids to show", default=cfg['max_pids'])
    parser.add_argument ("--threads", help="Include also threads in the output", action="store_true", default=False)
    parser.add_argument ("--include_self", help="Include also stats from this script", action="store_true", default=False)
    parser.add_argument ("--max_threads", type=int, help="Max num of threads per pid to show (requires --threads)", default=cfg['max_threads'])
    args = parser.parse_args()
    if args.max_pids is not None:
        cfg['max_pids'] = args.max_pids
    if args.max_threads is not None:
        cfg['max_threads'] = args.max_threads
    if args.threads:
        cfg['show_threads'] = True
    if args.include_self:
        cfg['include_self'] = True

def print_row(arr):
    for i in range(len(arr)):
        if i == 0:
            pad = 18
        else:
            pad = 10
        print ('{:<{}s}'.format(arr[i], pad), end="")

def pad_for_threads(ss=''):
    print ('\n{:>48}'.format(''), end="")
    print (ss, end="")

def sort_dict_by_val(d, rev=True):
    return sorted(d.items(), key=lambda item: item[1], reverse=rev)

def sort_nested_dic(d, col='score', rev=True):
    # currently not used
    return sorted(d.items(), key=lambda x: x[1]['score'], reverse=rev)

def get_pids(path = "/proc"):
    tmp_pid_list = []
    self_pid = str(os.getpid())

    # we'd like to determine if we are processing processes or tasks;
    # if this is a process, it will call itself recursively to process also tasks
    if path == "/proc":
        isTask = False
    else:
        isTask = True

    # all the integer directories in /proc are processes
    try:
        fobj = os.scandir(path)
    except:
        # pid or task is gone at this point
        return
    for item in fobj:
        
        if not cfg['include_self'] and item.name == self_pid:
            continue
            
        if item.is_dir() and item.name.isdigit():
            try:
                # verify if any file descriptors exist in the directory
                if any(os.scandir(path+"/"+item.name+"/fd")):
                    tmp_pid_list.append(item.name)
                    if not isTask:
                        pid_score[item.name] = 0
            except:
                continue
    return tmp_pid_list

def remove_pid(pid):
    # currently not used
    pid_list.remove(pid)
    pid_score.pop(pid)

def get_fd_type (s):
    # classify descriptors by type ; https://man7.org/linux/man-pages/man5/proc.5.html
    if "socket:" in s: return "socket"
    elif "anon_inode:" in s: return "anon_inode" # file descriptors produced by bpf(2), epoll_create(2), eventfd(2), inotify_init(2), perf_event_open(2), signalfd(2), timerfd_create(2), and userfaultfd(2)
    elif "/dev/" in s: return "dev"
    elif "pipe:" in s: return "pipe"
    elif "/sys/" in s: return "sys"
    elif "/run/" in s: return "run"
    elif "/proc/" in s: return "proc"

    # if fd is a file or keep the rest as unknown
    if os.path.isfile(s):
        return "file"
    else:
        return "unknown"

def get_comm(pid, path = ""):
    # get command name associated with the process/thread ; maximum TASK_COMM_LEN (16) characters
    if len(path) > 0:
        path = path + "/comm"
    else:
        path = "/proc/" + pid + "/comm"
    try:
        f = open(path)
        data = f.read().replace("\n", "")
        f.close()
        return data
    except:
        return "unknown"

def get_ppid(pid):
    # get parent pid
    try:
        f = open("/proc/"+pid+"/stat")
        data = f.read().replace("\n", "").split()
        f.close()
        return data[3]
    except:
        return "unknown"

def get_taskid(s):
    """ example: /proc/10067/task/15335/fd/55 """
    start = s.find('/task/') + 6
    return s[start:s.find('/fd/', start)]

def get_stats (pid, path = ""):
    # the main function to collect FD stats
    if len(path) > 0:
        path = path + "/fd/"
        isProcess = False # means this is a task/thread associated with pid, e.g /proc/pid/task/*
    else:
        path = "/proc/" + pid + "/fd/"
        isProcess = True

    try:
        fobj1 = os.scandir(path)
    except:
        # pid is gone, skipping
        return

    for item in fobj1:

        if item.is_symlink():
        # everything here should be symlink, but better be safe
            try:
                ll = os.readlink(item.path)
            except:
                # the FD has been closed by the time we got here
                continue

            # store the stats into relevant dictionaries
            pid_score[pid] += 1
            if pid_stats.get(pid) is None:
                pid_stats[pid] = {}

            if pid_extra.get(pid) is None:
               pid_extra[pid] = {}
            if isProcess:
                pid_extra[pid]['comm'] = get_comm(pid)
                pid_extra[pid]['ppid'] = get_ppid(pid)

            # in case threads stats are requested too
            if (not isProcess) and (cfg['show_threads']):
                t_id = get_taskid(item.path)

                if pid_threads.get(pid) is None:
                    pid_threads[pid] = {}
                comm = get_comm(pid, "/proc/"+pid+"/task/"+t_id)
                pid_threads[pid][comm] = pid_threads[pid].get(comm, 0)
                pid_threads[pid][comm] += 1

            fd_type = get_fd_type(ll)

            if pid_stats[pid].get(fd_type) is None:
                pid_stats[pid][fd_type] = 0
            pid_stats[pid][fd_type] += 1
            totals[fd_type] += 1

    if isProcess:
        # now prepare to call itself for the tasks (if any)
        tmp_pids = get_pids("/proc/" + pid + "/task")

        # single threaded process would create /proc/pid/task/fd/ with the same pid as the process and have exact same FDs
        # aka /prod/pid/task/pid ; this should be ignored
        try:
            tmp_pids.remove(pid)
        except:
            return
        
        for i in tmp_pids:
            get_stats (pid, "/proc/" + pid + "/task/" + i)

def print_totals():
    print ("Total number of open FDs: {}".format(sum(totals.values())))
    for k in sorted(totals):
        print ("\tTotal {} {}".format(k,totals[k]))

def print_pids():
    print_row(['Command', 'PID', 'PPID', 'FD count', 'FD types'])
    print()
    i = 0
    for pid,cnt in sort_dict_by_val(pid_score):
        i += 1
        # to limit output of pids
        if i > cfg['max_pids']:
            break
        print_row([pid_extra[pid]["comm"], pid, pid_extra[pid]["ppid"], str(cnt)])
        for kk in sorted(pid_stats[pid]):
            print ("{}({})".format(kk,pid_stats[pid][kk]), end=" ")

        # if requested to show tasks as well
        if cfg['show_threads']:

            if pid_threads.get(pid) is None:
                pad_for_threads ("(no_task)")
                print()
                continue

            j = 0
            # thread command (comm) and thread score
            for t_comm, t_score in sort_dict_by_val(pid_threads[pid]):
                pad_for_threads ("|- {}({})".format(t_comm, t_score, end=""))
                j += 1
                # to limit the output of tasks/threads
                if j == cfg['max_threads']:
                    break

        print()

### end functions

if __name__ == "__main__":
    parse_args()
    pid_list = get_pids()

    # use concurrent executor to speed up the execution
    with concurrent.futures.ThreadPoolExecutor ( max_workers = cfg['max_workers'] ) as executor:
        task = {executor.submit(get_stats, I):I for I in pid_list}
        for future in concurrent.futures.as_completed(task):
            future.result()

    print_totals()
    print_pids()
