# Description
Omnios r151046, kernel SunOS Omnios 5.11 has a connection abuse and illegitimate communication vulnerability. In LISTEN STATE, upon receiving an abnormal SYN+ACK, it is still regarded as valid input, resulting in the acceptance of an illegal connection request. Attackers can forge SYN+ACK packets to establish malicious connections, bypassing normal authentication and enabling unauthorized communication, ultimately leading to connection abuse and illegitimate communication.

# Reproduction
## Environment
* Test machine - virtual machine 1: The system is not limited, such as Ubuntu system. Python, scapy, pcapy, impacket environments are installed. IP1: 192.168.56.111 
* Target system - virtual machine 2: OmniOS operating system. GCC runtime environment is installed. IP2: 192.168.56.109
* The two virtual machines can communicate over the network.

## Experiment Overview
Virtual machine 1 sends a packet or system call to virtual machine 2 of the omnios system. The sending sequence is LISTEN, SYN+ACK(V,V). The response of virtual machine 2 after receiving SYN+ACK(V,V) packet is mainly observed. If virtual machine 2 responds with SYN+ACK after receiving SYN+ACK(V,V) packet, there is a vulnerability. 
* Note1: LISTEN means notifying virtual machine 2 to system call listen as a server. The remaining SYN+ACK(V,V) represent TCP packets of different flags. The first bit in the bracket represents the sequence number, and the second bit represents the acknowledgment number. Each bit is divided into two categories: V and INV. ​​In general​​, V means valid - this value is equal to the expected exact value of normal communication, and INV means invalid - this value does not exactly match the expected exact value and is within the receiving window range. 0 means - the value is 0.

## Files Preparation
* File [poc.py](https://github.com/zq-star/TCP-Vuln-Report/blob/master/Omnios-r151046-5.11/tcp-flag-validation/poc.py): Located in test machine - virtual machine 1 environment. Poc is responsible for sending corresponding data packets according to specified order. 
* File [socketAdapter.c](https://github.com/zq-star/TCP-Vuln-Report/blob/master/Omnios-r151046-5.11/SutAdapter/socketAdapter.c)[^socketAdapterCode]: Located in target system - virtual machine 2 environment. System call may be required in the implementation of TCP. The socketAdapter.c file is mainly responsible for identifying received commands and making system calls according to commands. For example: if “listen” is received, virtual machine 2 will initiate a connection as a server. In addition, socketAdapter.c will generate new port value of actual communication process and pass it to the test end-virtual machine 1, which will be used as the communication port of target system end.

## Reproduction steps
1. In target system - virtual machine 2:
   * Run `gcc -Wall -pthread -o socketAdapter.o socketAdapter.c -lnsl -lsocket`. Compile socketAdapter.c and generate the socketAdapter.o executable file. 
   * Run `sudo nice -19 ./socketAdapter.o -a 192.168.56.111 -l 5000 -p 20000`. Make target system in state of listening to commands.
2. In test machine - virtual machine 1:
   * Run `sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP`. This step is to avoid interference caused by automatic packet sending by system kernel of virtual machine 1.
   * Run `sudo python poc.py`. The [poc.py](https://github.com/zq-star/TCP-Vuln-Report/blob/master/Omnios-r151046-5.11/tcp-flag-validation/poc.py) sends packets of specified types in order: LISTEN, SYN(V,0), ACK(V,V), ACCEPT, CLOSECONNECTION, SYN(INV, 0).
3. Capture packets to observe responses of omnios system - virtual machine 2 during running [poc.py](https://github.com/zq-star/TCP-Vuln-Report/blob/master/Omnios-r151046-5.11/tcp-syn-in-fin-wait-1/poc.py):
![packets](https://github.com/zq-star/TCP-Vuln-Report/blob/master/Omnios-r151046-5.11/pictures/tcp-flag-validation.png)
   * First, a socket connection is automatically established to pass command, and virtual machine 2 transmits actual communication port of local end，which is used for the following communication test of packets in order.
   * Virtual machine 1 sends LISTEN. At this time, virtual machine 2 is in LISTEN STATE.
   * Virtual machine 1 sends an abnormal SYN+ACK, virtual machine 2 responds with SYN+ACK, indicating that Omnios incorrectly checks the flag field in LISTEN, allowing illegal connection requests. Attackers can forge SYN+ACK packets to establish malicious connections, bypassing normal authentication and enabling unauthorized communication, ultimately leading to connection abuse and illegitimate communication.
  
[^socketAdapterCode]: Minor changes based on work of [ Fiterău-Broştean, Paul, Ramon Janssen, and Frits Vaandrager. "Combining model learning and model checking to analyze TCP implementations." Computer Aided Verification: 28th International Conference, CAV 2016, Toronto, ON, Canada, July 17-23, 2016, Proceedings, Part II 28. Springer International Publishing, 2016. ]




