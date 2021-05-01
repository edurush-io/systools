# systools
Various Linux System Tools

- [scan_network.py](scan_network.py): fast CIDR scanner reporting Up/Down for each IP in the subnet (_requires Python 3_)
- [connection_stats.py](connection_stats.py): quick report on protocols (tcp (4/6) and udp(4/6)) and port utilization within a system (requires Python 3)

# Example usage
- **scan_network.py** - fast CIDR scanner reporting Up/Down for each IP in the subnet (_requires Python 3_)
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

- **connection_stats.py** - quick report on protocols (tcp (4/6) and udp(4/6)) and port utilization within a system (requires Python 3)
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
