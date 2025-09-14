# Description
PLC Simens-300 with firmware version v3.3.17 has a denial of service vulnerability. For the processing of TCP SYN packets in SYN-RECEIVED STATE, PLC Simens-300 has a wide acceptable range of sequence numbers. It does not require the sequence number to exactly match the next expected sequence value, just to be within the current receive window. This flaw allows attackers to send multiple random TCP SYN packets to hit the acceptable range of sequence numbers, thereby interrupting the ongoing connection process and causing a denial of service attack.

# Reproduction
## Environment
* Test host: IP1 - 192.168.1.31
* PLC Simens-300: TCP communication open port - 102; IP2 - 192.168.1.201
* The test host and PLC Simens-300 are directly connected via a network cable.

## Reproduction steps
1. In test host:
   * Run `sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP`. This step is to avoid interference caused by automatic packet sending by system kernel of test host.
   * Run `sudo python poc.py`. 
3. Capture packets to observe communication process during running [poc.py](https://github.com/zq-star/TCP-Vuln-Report/blob/master/PLC/Simens-300/tcp-syn-in-syn-received/poc.py):
   * Test host sends a SYN to PLC, PLC responds with SYN+ACK and in SYN-RECEIVED STATE.
![packets1](https://github.com/zq-star/TCP-Vuln-Report/blob/master/PLC/pictures/simens-300/siemens-300-tcp-syn-in-syn-received-1.png)
   * Test host sends a SYN packet with a sequence number within the receive window again, PLC responds with RST+ACK, indicating that the ongoing connection process is interrupted. ![packets2](https://github.com/zq-star/TCP-Vuln-Report/blob/master/PLC/pictures/simens-300/siemens-300-tcp-syn-in-syn-received-2.png)
   * Test host sends a new SYN packet again, PLC responds with SYN+ACK, indicating that new connection request can be accepted. ![packets3](https://github.com/zq-star/TCP-Vuln-Report/blob/master/PLC/pictures/simens-300/siemens-300-tcp-syn-in-syn-received-3.png)
  
The above process demonstrates that a SYN packet with a sequence number within the current receive window in SYN-RECEIVED STATE can directly disconnect the ongoing connection process, causing the connection to be interrupted.





