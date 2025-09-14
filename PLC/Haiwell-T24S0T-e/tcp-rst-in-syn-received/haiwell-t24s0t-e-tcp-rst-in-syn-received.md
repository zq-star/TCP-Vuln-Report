# Description
PLC Haiwell T24S0T_E with firmware version V2.2.13 has a denial of service vulnerability. For the processing of TCP RST packets in SYN-RECEIVED STATE, PLC Haiwell T24S0T_E has a wide acceptable range of sequence numbers. It does not require the sequence number to exactly match the next expected sequence value, just to be within the current receive window. This flaw allows attackers to send multiple random TCP RST packets to hit the acceptable range of sequence numbers, thereby interrupting the ongoing connection process and causing a denial of service attack.

# Reproduction
## Environment
* Test host: IP1 - 192.168.1.31
* PLC Haiwell T24S0T_E: TCP communication open port - 502; IP2 - 192.168.1.24
* The test host and PLC Haiwell T24S0T_E are directly connected via a network cable.

## Reproduction steps
1. In test host:
   * Run `sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP`. This step is to avoid interference caused by automatic packet sending by system kernel of test host.
   * Run `sudo python poc.py`. 
3. Capture packets to observe communication process during running [poc.py](https://github.com/zq-star/TCP-Vuln-Report/blob/master/PLC/Haiwell-T24S0T-e/tcp-rst-in-syn-received/poc.py):
   * Test host sends a SYN to PLC, PLC responds with SYN+ACK and in SYN-RECEIVED STATE.
![packets1](https://github.com/zq-star/TCP-Vuln-Report/blob/master/PLC/pictures/simens-300/siemens-300-tcp-rst-in-syn-received-1.png)
   * Test host sends two RST packets with the sequence number within the receive window again, PLC does not respond. ![packets2](https://github.com/zq-star/TCP-Vuln-Report/blob/master/PLC/pictures/simens-300/siemens-300-tcp-rst-in-syn-received-2.png)
   * Test host sends a new SYN packet again, PLC responds with SYN+ACK, indicating that the old ongoing connection process is interrupted by RST packets within the receive window and the new connection request is accepted. ![packets3](https://github.com/zq-star/TCP-Vuln-Report/blob/master/PLC/pictures/simens-300/siemens-300-tcp-rst-in-syn-received-3.png)
  
The above process demonstrates that RST packets with a sequence number within the current receive window in SYN-RECEIVED STATE can directly disconnect the ongoing connection process, causing the connection to be interrupted.







