# Description
Schneider Modicon M with firmware version V1.13.0.1 has a denial of service vulnerability. When processing TCP RST packets, PLC M221 will incorrectly accept RST packets with arbitrary sequence numbers, which violates RFC793. This vulnerability allows attackers to send forged TCP RST packets, thereby interrupting normal connections and causing a denial of service attack.

# Reproduction
## Environment
* Test host: IP1 - 192.168.1.31
* PLC M221: TCP communication open port - 502; IP2 - 192.168.1.221
* The test host and PLC M221 are directly connected via a network cable.

## Reproduction steps
1. In test host:
   * Run `sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP`. This step is to avoid interference caused by automatic packet sending by system kernel of virtual machine 1.
   * Run `sudo python poc.py`. 
3. Capture packets to observe communication process during running [poc.py](https://github.com/zq-star/TCP-Vuln-Report/blob/master/PLC/Schneider-M221/tcp-rst/poc.py):
   * Test host establishes a TCP connection with PLC.
![packets1](https://github.com/zq-star/TCP-Vuln-Report/blob/master/PLC/pictures/schneider-m221/m221-tcp-rst-1.png)
   * Test host sends an ACK packet with a matching sequence number, and PLC does not respond normally.
![packets2](https://github.com/zq-star/TCP-Vuln-Report/blob/master/PLC/pictures/schneider-m221/m221-tcp-rst-2.png)
   * Test host sends a RST with an arbitrary sequence number to PLC, trying to terminate the connection.
![packets3](https://github.com/zq-star/TCP-Vuln-Report/blob/master/PLC/pictures/schneider-m221/m221-tcp-rst-3.png)
   * Test host sends an ACK packet with a matching sequence number to PLC again, to verify whether the connection is disconnected. PLC responds with an RST to test host, indicating that the connection is disconnected.
![packets4](https://github.com/zq-star/TCP-Vuln-Report/blob/master/PLC/pictures/schneider-m221/m221-tcp-rst-4.png)
  
The above process demonstrates that a RST packet with an arbitrary sequence number can directly disconnect the TCP connection, causing the connection to be interrupted.


