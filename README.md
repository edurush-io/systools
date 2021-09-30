# systools
Various Linux System Tools

- [scan_network.py](scan_network.py): fast CIDR scanner reporting Up/Down for each IP in the subnet (_Python 3_)
- [connection_stats.py](connection_stats.py): quick report on protocols (tcp (4/6) and udp(4/6)) and port utilization within a system (_Python 3_)
- [lsod.py](lsod.py): list of file descriptors (alternate lsof) - very fast statistics on file descriptors per process/thread (_Python 3_)
- [python_multicast.py](python_multicast.py): Send/receive UDP multicast packets (_Python 3_)

# Example usage
### scan_network.py - fast CIDR scanner reporting Up/Down for each IP in the subnet (_requires Python 3_)
```
usage: scan_network.py CIDR (e.g. abc.def.gh.yz/nn)

Quick network CIDR scanner

positional arguments:
  cidr        CIDR block

optional arguments:
  -h, --help  show this help message and exit
  --fast      make it faster
  --ufast     ultra fast
```
Sample output:
```
~# scan_network.py 10.11.1.0/24
10.11.1.1 is Up
10.11.1.2 is Up
10.11.1.3 is Down
...
Total up: 110
Total down: 144
Total unknown: 0
```

### connection_stats.py - quick report on protocols (tcp (4/6) and udp(4/6)) and port utilization within a system (requires Python 3)
```
usage: connection_stats.py [--ver=tcp|tcp4|tcp6|udp|udp4|udp6|all] (default is tcp which is tcp4 connections)

Script to analyze connections and report usage

optional arguments:
  -h, --help     show this help message and exit
  --ver VER      What to report: version of protocol
                 tcp|tcp4|tcp6|udp|udp4|udp6 or all together)
  --limit LIMIT  How many top consumers to report; number or 'all')
```
Sample output:
```
~# connection_stats.py
------------------ tcp : states: total 63061; unique 9 ------------------
 ESTABLISHED : 39648
 TCP_TIME_WAIT : 22785
 TCP_FIN_WAIT2 : 519
 TCP_CLOSE_WAIT : 41
 TCP_FIN_WAIT1 : 18
 TCP_SYN_RECV : 16
 TCP_LAST_ACK : 13
 TCP_SYN_SENT : 12
 TCP_LISTEN : 9
------------------ tcp : remote_port: total 63061; unique 25567 ------------------
 80 : 8693
 53000 : 33
 59658 : 11
 53936 : 10
 45432 : 10
 50816 : 10
 34134 : 10
 60750 : 10
 59604 : 10
 45130 : 10
------------------ tcp : remote_ip: total 63061; unique 11520 ------------------
 aaa.bbb.cc.ddd : 214
 aaa.bbb.cc.ddd : 205
 aaa.bbb.cc.ddd : 181
 aaa.bbb.cc.ddd : 180
 aaa.bbb.cc.ddd : 179
 aaa.bbb.cc.ddd : 179
 aaa.bbb.cc.ddd : 176
 aaa.bbb.cc.ddd : 171
 aaa.bbb.cc.ddd : 170
 aaa.bbb.cc.ddd : 166
------------------ tcp : local_port: total 63061; unique 7675 ------------------
 80 : 51760
 443 : 2565
 55630 : 4
 16088 : 3
 19158 : 3
 27912 : 3
 24470 : 3
 54464 : 3
 40672 : 3
 54882 : 3
```

### lsod.py - list of file descriptors (alternate lsof) - very fast statistics on file descriptors per process/thread 
```
usage: lsod.py

Very fast file descriptor usage report

optional arguments:
  -h, --help            show this help message and exit
  --max_pids MAX_PIDS   Max num of pids to show
  --threads             Include also threads in the output
  --include_self        Include also stats from this script
  --max_threads MAX_THREADS
                        Max num of threads per pid to show (requires --threads)

```
lsod sample output 1:
```
Total number of open fds: 3114035
        Total anon_inode 551623
        Total dev 5755
        Total file 415373
        Total pipe 614524
        Total proc 305
        Total run 54
        Total socket 1526388
        Total sys 4
        Total unknown 9
Command           PID       PPID      FD count  FD types
java              870       1         3094938   anon_inode(549601) dev(5013) file(411312) pipe(613568) socket(1515444)
java              1171      1         13770     anon_inode(340) dev(255) file(3060) pipe(510) socket(9605)
mongod            2252      1         2808      anon_inode(1287) dev(195) file(819) socket(507)
icinga2           18024     1         1344      anon_inode(256) dev(64) file(96) pipe(256) run(32) socket(640)
python3           15485     14584     408       dev(111) proc(297)
nxlog             30613     1         348       anon_inode(72) dev(36) file(72) pipe(144) run(12) socket(12)
salt-minion       24344     24335     100       anon_inode(32) dev(12) pipe(24) socket(28) unknown(4)
systemd           1         0         55        anon_inode(10) dev(6) pipe(1) proc(2) run(3) socket(32) sys(1)
rsyslogd          1269      1         36        dev(12) file(12) proc(4) socket(8)
systemd-journal   909       1         28        anon_inode(5) dev(5) run(2) socket(15) sys(1)
```
lsod.py sample output 2 (with threads):
```
Total number of open fds: 430472
        Total anon_inode 2972
        Total dev 1378
        Total file 53541
        Total pipe 5995
        Total proc 179
        Total run 53
        Total socket 366346
        Total sys 4
        Total unknown 4
Command           PID       PPID      FD count  FD types
java              8673      1         428090    anon_inode(2576) dev(1104) file(53360) pipe(5536) socket(365514)
                                                |- ExecutorService(163564)
                                                |- qtp1055096410-7(112490)
                                                |- cluster-Cluster(17452)
                                                |- C3P0PooledConne(16200)
                                                |- ContextualDataL(5779)
                                                |- ForkJoinPool.co(3493)
                                                |- RMI TCP Accept-(3475)
                                                |- TargetedContext(2321)
                                                |- qtp1055096410-4(2315)
                                                |- OperatingSystem(2310)
icinga2           15200     1         1344      anon_inode(256) dev(64) file(96) pipe(256) run(32) socket(640)
                                                |- icinga2(1302)
nxlog             4524      1         348       anon_inode(72) dev(36) file(72) pipe(144) run(12) socket(12)
                                                |- nxlog(319)
python3           24116     12771     261       dev(90) proc(171)
                                                |- python3(240)
salt-minion       1531      1523      124       anon_inode(32) dev(12) pipe(48) socket(28) unknown(4)
                                                |- salt-minion(93)
systemd           1         0         56        anon_inode(10) dev(6) pipe(1) proc(2) run(3) socket(33) sys(1)
                                                (no_task)
rsyslogd          8571      1         36        dev(12) file(12) proc(4) socket(8)
                                                |- in:imuxsock(9)
                                                |- in:imklog(9)
                                                |- rs:main Q:Reg(9)
systemd-journal   950       1         28        anon_inode(5) dev(5) run(1) socket(16) sys(1)
                                                (no_task)
ntpd              1959      1         24        dev(6) socket(18)
                                                |- ntpd(12)
systemd           27607     1         22        anon_inode(5) dev(1) proc(2) socket(13) sys(1)
                                                (no_task)
```

### python_multicast.py - Send/receive UDP multicast packets (_requires Python 3_)
```
usage: python_multicast.py --send|--receive --ip=MCAST_IP --port=MCAST_PORT

Python multicast send/receive

optional arguments:
  -h, --help         show this help message and exit
  --ip IP            IP for Multicast Group
  --port PORT        Port for Multicast Group
  --send             Send multicast
  --receive          Receive multicast
  --message MESSAGE  Message for Multicast Group (optional)
```
