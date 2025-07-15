# Description
PLC Simens-300 with firmware version v3.3.17 has a denial of service vulnerability. For the processing of TCP SYN packets, PLC Simens-300 has a wide acceptable range of sequence numbers. It does not require the sequence number to exactly match the next expected sequence value, just to be within the current receive window. This flaw allows attackers to send multiple random TCP SYN packets to hit the acceptable range of sequence numbers, thereby interrupting normal connections and causing a denial of service attack.

# Reproduction
## Environment
* Test host: IP1 - 192.168.1.31
* PLC Simens-300: TCP communication open port - 502; IP2 - 192.168.1.201
* The test host and PLC Simens-300 are directly connected via a network cable.

## Reproduction steps
1. In test host:
   * Run `sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP`. This step is to avoid interference caused by automatic packet sending by system kernel of test host.
   * Run `sudo python poc.py`. 
3. Capture packets to observe communication process during running [poc.py](https://github.com/zq-star/TCP-Vuln-Report/blob/master/PLC/Simens-300/tcp-syn/poc.py):
   * Test host establishes a TCP connection with PLC.
![packets1](https://github.com/zq-star/TCP-Vuln-Report/blob/master/PLC/pictures/simens-300/simens-300-tcp-syn-1.png)
   * Test host sends an ACK packet with a matching sequence number, and PLC does not respond normally.
![packets2](https://github.com/zq-star/TCP-Vuln-Report/blob/master/PLC/pictures/simens-300/simens-300-tcp-syn-2.png)
   * Test host sends multiple SYN packets with different sequence numbers to PLC, trying to terminate the connection. Generate an initial sequence number within 0 - current receive window value, and increment by the window value to traverse all window intervals in entire sequence number space. The window size tested is 2048. (For intuitiveness, the above picture shows the SYN packet directly sent with a sequence number within the receive window.)
![packets3](https://github.com/zq-star/TCP-Vuln-Report/blob/master/PLC/pictures/simens-300/simens-300-tcp-syn-3.png)
   * Test host sends an ACK packet with a matching sequence number to PLC again, to verify whether the connection is disconnected. PLC responds with a RST to test host, indicating that the connection is disconnected.
![packets4](https://github.com/zq-star/TCP-Vuln-Report/blob/master/PLC/pictures/simens-300/simens-300-tcp-syn-4.png)
  
The above process demonstrates that a SYN packet with a sequence number within the current receive window can directly disconnect the TCP connection, causing the connection to be interrupted.




