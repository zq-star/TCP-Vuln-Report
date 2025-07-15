# Description
Delta PLC DVP80ES3 with firmware version v01.06.00 has a denial of service vulnerability. When processing TCP RST/SYN packets, PLC DVP80ES3 will incorrectly accept RST/SYN packets with arbitrary sequence numbers, which violates RFC793. This vulnerability allows attackers to send forged TCP RST/SYN packets, thereby interrupting normal connections and causing a denial of service attack.

# Reproduction
## Environment
* Test host: IP1 - 192.168.1.31
* PLC DVP80ES3: TCP communication open port - 502; IP2 - 192.168.1.5
* The test host and PLC DVP80ES3 are directly connected via a network cable.

## Reproduction steps
1. In test host:
   * Run `sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP`. This step is to avoid interference caused by automatic packet sending by system kernel of test host.
   * Run `sudo python poc_rst.py` or `sudo python poc_syn.py`. 
3. Capture packets to observe communication process during running [poc_rst.py](https://github.com/zq-star/TCP-Vuln-Report/blob/master/PLC/Delta-DVP80ES3/tcp-rst-syn/poc_rst.py) or [poc_syn.py](https://github.com/zq-star/TCP-Vuln-Report/blob/master/PLC/Delta-DVP80ES3/tcp-rst-syn/poc_syn.py) respectively:
   * Test host establishes a TCP connection with PLC.
![packets-rst1](https://github.com/zq-star/TCP-Vuln-Report/blob/master/PLC/pictures/delta-dvp80es3/delta-dvp80es3-tcp-rst-1.png) ![packets-syn1](https://github.com/zq-star/TCP-Vuln-Report/blob/master/PLC/pictures/delta-dvp80es3/delta-dvp80es3-tcp-syn-1.png)
   * Test host sends an ACK packet with a matching sequence number, and PLC does not respond normally.
![packets-rst2](https://github.com/zq-star/TCP-Vuln-Report/blob/master/PLC/pictures/delta-dvp80es3/delta-dvp80es3-tcp-rst-2.png) ![packets-syn2](https://github.com/zq-star/TCP-Vuln-Report/blob/master/PLC/pictures/delta-dvp80es3/delta-dvp80es3-tcp-syn-2.png)
   * Test host sends a RST/SYN with an arbitrary sequence number to PLC, trying to terminate the connection.
![packets-rst3](https://github.com/zq-star/TCP-Vuln-Report/blob/master/PLC/pictures/delta-dvp80es3/delta-dvp80es3-tcp-rst-3.png) ![packets-syn3](https://github.com/zq-star/TCP-Vuln-Report/blob/master/PLC/pictures/delta-dvp80es3/delta-dvp80es3-tcp-syn-3.png)
   * Test host sends an ACK packet with a matching sequence number to PLC again, to verify whether the connection is disconnected. PLC responds with an RST+ACK to test host, indicating that the connection is disconnected.
![packets-rst4](https://github.com/zq-star/TCP-Vuln-Report/blob/master/PLC/pictures/delta-dvp80es3/delta-dvp80es3-tcp-rst-4.png) ![packets-syn4](https://github.com/zq-star/TCP-Vuln-Report/blob/master/PLC/pictures/delta-dvp80es3/delta-dvp80es3-tcp-syn-4.png)
  
The above process demonstrates that a RST/SYN packet with an arbitrary sequence number can directly disconnect the TCP connection, causing the connection to be interrupted.



