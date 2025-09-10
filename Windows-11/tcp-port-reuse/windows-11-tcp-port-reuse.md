# Description
Windows 11, kernel 22621.2861 has a denial of service vulnerability. In SYN-RECEIVED state, after receiving a valid RST to close the connection, when executing CONNECT again, the local communication port for SYN request will still be the same as the one used in the old connection. An attacker can exploit this
fixed port behavior, sending a large number of malicious requests to target port, which overloads the port and exhausts resources.

# Reproduction
## Environment
* Test machine - virtual machine 1: The system is not limited, such as Ubuntu system. Python, scapy, pcapy, impacket environments are installed. IP1: 192.168.56.111 
* Target system - virtual machine 2: Windows operating system. GCC runtime environment is installed. IP2: 192.168.56.115
* The two virtual machines can communicate over the network.

## Experiment Overview
Virtual machine 1 sends a packet or system call to virtual machine 2 of the Windows system. The sending sequence is CONNECT, SYN(V, V), RST(V, 0), CONNECT. The response of virtual machine 2 after receiving the second CONNECT system call command is mainly observed. If the SYN packet responded by virtual machine 2 after invoking CONNECT again uses the same local port as the old connection, a port reuse vulnerability exists.

* Note1: CONNECT means notifying virtual machine 2 to system call connect as a client. The remaining SYN(V, V) and RST(V, 0) represent TCP packets of different flags. The first bit in the bracket represents the sequence number, and the second bit represents the acknowledgment number. Each bit is divided into two categories: V and INV. ​​In general​​, V means valid - this value is equal to the expected exact value of normal communication, and INV means invalid - this value does not exactly match the expected exact value and is within the receiving window range. 0 means - the value is 0.

## Files Preparation
* File [poc.py](https://github.com/zq-star/TCP-Vuln-Report/blob/master/Windows-11/tcp-port-reuse/poc.py): Located in test machine - virtual machine 1 environment. Poc is responsible for sending corresponding data packets according to specified order. 
* File [socketAdapter.c](https://github.com/zq-star/TCP-Vuln-Report/blob/master/Windows-11/SutAdapter/socketAdapter.c)[^socketAdapterCode]: Located in target system - virtual machine 2 environment. System call may be required in the implementation of TCP. The socketAdapter.c file is mainly responsible for identifying received commands and making system calls according to commands. For example: if “connect” is received, virtual machine 2 will initiate a connection as a client. In addition, socketAdapter.c will generate new port value of actual communication process and pass it to the test end-virtual machine 1, which will be used as the communication port of target system end.

## Reproduction steps
1. In target system - virtual machine 2:
   * Run `cl socketAdapter.c`. Compile socketAdapter.c and generate the socketAdapter.o executable file. 
   * Run `.\socketAdapter -a 192.168.56.104 -c -l 5000 -p 20000`. Make target system in state of listening to commands.
2. In test machine - virtual machine 1:
   * Run `sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP`. This step is to avoid interference caused by automatic packet sending by system kernel of virtual machine 1.
   * Run `sudo python poc.py`. The [poc.py](https://github.com/zq-star/TCP-Vuln-Report/blob/master/Openindiana%20minimal/tcp-syn-in-fin-wait-1/poc.py) sends packets of specified types in order: CONNECT, SYN(V, V), RST(V, 0), CONNECT.
3. Capture packets to observe responses of Windows system - virtual machine 2 during running [poc.py](https://github.com/zq-star/TCP-Vuln-Report/blob/master/Openindiana%20minimal/tcp-syn-in-fin-wait-1/poc.py):
![packets](https://github.com/zq-star/TCP-Vuln-Report/blob/master/Windows-11/pictures/tcp-port-reuse.png)
   * First, a socket connection is automatically established to pass command, and virtual machine 2 transmits actual communication port of local end，which is used for the following communication test of packets in order.
   * Virtual machine 1 sends CONNECT, virtual machine 2 responds with SYN. At this time, virtual machine 2 is in SYN-SENT STATE.
   * Virtual machine 1 sends SYN(V, V), virtual machine 2 responds with SYN+ACK. At this time, virtual machine 2 is in SYN-RECEIVED STATE.
   * Virtual machine 1 sends RST(V, 0) to close the current connection.
   * Virtual machine 1 sends a CONNECT system call command again. Virtual machine 2 responds with a SYN packet using the same local communication port as the previous connection, indicating the flaw of port reuse. An attacker can exploit this fixed port behavior, sending a large number of malicious requests to target port, which overloads the port and exhausts resources.
  
[^socketAdapterCode]: Minor changes based on work of [ Fiterău-Broştean, Paul, Ramon Janssen, and Frits Vaandrager. "Combining model learning and model checking to analyze TCP implementations." Computer Aided Verification: 28th International Conference, CAV 2016, Toronto, ON, Canada, July 17-23, 2016, Proceedings, Part II 28. Springer International Publishing, 2016. ]




