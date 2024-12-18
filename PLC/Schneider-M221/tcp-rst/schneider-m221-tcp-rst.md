# Description
Schneider Modicon TM221CE40T with firmware version V1.13.0.1 has a denial of service vulnerability. When processing TCP RST packets, PLC M221 will incorrectly accept RST packets with arbitrary sequence numbers, which violates RFC793. This vulnerability allows attackers to send forged TCP RST packets, thereby interrupting normal connections and causing a denial of service attack.

# Reproduction
## Environment
* Test host: IP1 - 192.168.1.31
* PLC M221: TCP communication open port - 502; IP2 - 192.168.1.221
* The test host and PLC M221 are directly connected via a network cable.

## Reproduction steps
1. In target system - virtual machine 2:
   * Run `gcc -Wall -pthread -o socketAdapter.o socketAdapter.c -lnsl -lsocket`. Compile socketAdapter.c and generate the socketAdapter.o executable file. 
   * Run `sudo nice -19 ./socketAdapter.o -a 192.168.56.104 -l 5000 -p 20000`. Make target system in state of listening to commands.
2. In test machine - virtual machine 1:
   * Run `sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP`. This step is to avoid interference caused by automatic packet sending by system kernel of virtual machine 1.
   * Run `sudo python poc.py`. The [poc.py](https://github.com/zq-star/TCP-Vuln-Report/blob/master/Omnios-r151046-5.11/tcp-rst/poc.py) sends packets of specified types in order: CONNECT, SYN+ACK(V, V), PUSH+ACK(V, V), RST(INV, 0), and PUSH+ACK(V, V).
3. Capture packets to observe responses of omnios system - virtual machine 2 during running [poc.py](https://github.com/zq-star/TCP-Vuln-Report/blob/master/Omnios-r151046-5.11/tcp-rst/poc.py):
   * First, a socket connection is automatically established to pass command, and virtual machine 2 transmits actual communication port of local end，which is used for the following communication test of packets in order.
   * Virtual machine 1 sends CONNECT and SYN+ACK(V, V), virtual machine 2 responds with SYN and ACK respectively. At this time, TCP has established a connection.
   * Virtual machine 1 continues to send PUSH+ACK(V, V) with a 1-byte payload. Virtual machine 2 responds with a valid ACK, indicating that data can be transmitted normally.
   * Virtual machine 1 sends multiple RST packets with different sequence numbers.Generate an initial sequence number within 0 - current receive window value, and increment by the window value to traverse all window intervals in entire sequence number space. The window size tested is 65392. Virtual machine 2 does not respond.
   * Virtual machine 1 continues to send PUSH+ACK(V, V) for normal communication. Virtual machine 2 responds with RST, indicating that communication has been interrupted, causing a denial of service attack.
  
[^socketAdapterCode]: Minor changes based on work of [ Fiterău-Broştean, Paul, Ramon Janssen, and Frits Vaandrager. "Combining model learning and model checking to analyze TCP implementations." Computer Aided Verification: 28th International Conference, CAV 2016, Toronto, ON, Canada, July 17-23, 2016, Proceedings, Part II 28. Springer International Publishing, 2016. ]

