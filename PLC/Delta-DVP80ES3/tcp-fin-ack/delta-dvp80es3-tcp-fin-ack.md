# Description
Delta PLC DVP80ES3 with firmware version v01.06.00 has a denial of service vulnerability. When processing TCP FIN+ACK packets during TCP three-Way handshake process, PLC DVP80ES3 will temporarily stop responding for a period of time, rather than properly continuing TCP four-way handshake process to return to the closed state. This flaw causes PLC DVP80ES3 to fail in properly closing the original connection within a certain period after receiving FIN+ACK packets, while simultaneously preventing new connections from being established, ultimately resulting in a denial of service condition.

# Reproduction
## Environment
* Test host: IP1 - 192.168.1.31
* PLC DVP80ES3: TCP communication open port - 502; IP2 - 192.168.1.5
* The test host and PLC DVP80ES3 are directly connected via a network cable.

## Reproduction steps
1. In test host:
   * Run `sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP`. This step is to avoid interference caused by automatic packet sending by system kernel of test host.
   * Run `sudo python poc_fin_ack.py`. 
3. Capture packets to observe communication process during running [poc_fin_ack.py](https://github.com/zq-star/TCP-Vuln-Report/blob/master/PLC/Delta-DVP80ES3/tcp-fin-ack/poc_fin_ack.py):
   * During the connection process between test host and PLC, when test host sends FIN+ACK and ACK packets (TCP termination handshake), PLC fails to respond. This indicates that PLC does not properly handle the connection teardown process. Consequently, when a new SYN packet is sent to establish a fresh connection, PLC responds with RST+ACK, rejecting the new connection attempt and resulting in a denial of service.
![packets1](https://github.com/zq-star/TCP-Vuln-Report/blob/master/PLC/pictures/delta-dvp80es3/delta-dvp80es3-tcp-fin-ack-1.png)





