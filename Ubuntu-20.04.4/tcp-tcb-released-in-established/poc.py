# -*- coding: utf-8 -*-
import socket
import random
import time

from math import ceil
from pcapy import open_live
from impacket.ImpactDecoder import EthDecoder,Dot11WPA2Decoder
from impacket.ImpactPacket import IP, TCP

from scapy.all import IP as ScapyIP, TCP as ScapyTCP
from scapy.all import sr1, send, Raw

import time
import threading

import re

# 配置信息
SERVER_WINDOWS = 60000
SERVER_ADDR = '192.168.56.114'  # SUT IP地址:115-Windows, 114-ubuntu(host-own), omnios-109(host2), openindiana-105(host2), ghostBSD-108(host2) 
SERVER_CMD_PORT = 5000  # 连接的CMD socket的目的端口，用于传递指令
LEARNER_PORT = 20000 #学习端的端口
WAIT_TIME = 0.6 #抓包等待时间

global last_new_ports
global last_syn_responses
last_new_ports = dict() #获取上一个新的SUT端的通信端口
last_syn_responses = dict() #获取上一个SYN包的回应

# 创建 socket 客户端
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

def connect_to_server():
    """连接到服务器，并保持连接"""
    try:
        # 连接到服务器
        client_socket.connect((SERVER_ADDR, SERVER_CMD_PORT))
        print("Connected to server at {}:{}".format(SERVER_ADDR, SERVER_CMD_PORT))
    except Exception as e:
        print("Error occurred while connecting:", e)
        client_socket.close()
        raise

def send_message(message):
    """通过socket发送字符串指令消息"""
    try:
        # 将消息编码为UTF-8并发送
        client_socket.send(message.encode('utf-8'))
        print("Sent: {}".format(message))
    except Exception as e:
        print("Error occurred while sending message:", e)
    
# This is method is called periodically by pcapy
def callback(hdr,data):
    if data is None:
        return
    try:
        packet = EthDecoder().decode(data)
    except Exception:
        return
    if packet is None:
        return
    l2 = packet.child()
    if isinstance(l2,IP):
        l3 = l2.child()
        #Due to the filter used, all packets should use TCP
        src_ip = l2.get_ip_src()
        dst_ip = l2.get_ip_dst()
        tcp_src_port = l3.get_th_sport()
        tcp_dst_port = l3.get_th_dport()
        tcp_syn = l3.get_th_seq()
        tcp_ack = l3.get_th_ack()
        if l3.get_ACK() and l3.get_PSH() and tcp_src_port == SERVER_CMD_PORT:            
            last_new_ports[tcp_src_port] = process_cmd_pa_packet(l3)
        if l3.get_SYN() and tcp_dst_port == LEARNER_PORT:
            #process_cmd_pa_packet()
            last_syn_responses[tcp_dst_port] = [tcp_src_port, tcp_dst_port, tcp_syn, tcp_ack]
            
def process_cmd_pa_packet(l3):
    sut_port = 30000
    if l3.get_data_as_string():  # 确保数据包中有有效数据
        data = l3.get_data_as_string().strip() #去掉换行符
        # 打印数据部分（Raw）       
        # 假设数据格式是 "port+数字"，例如 "port56413"
        match = re.search(r'port (\d+)', data)
        # print match
        if match:
            # 提取数字部分并赋值给端口变量
            sut_port = int(match.group(1))
            print("Extracted Port Number:")
            print sut_port
    return sut_port 
           
def track_packets():
    pcap = open_live('enp0s8', 1024, False, 1)
    pcap.setfilter("tcp and (tcp src port " + str(SERVER_CMD_PORT) + " or tcp dst port " + str(LEARNER_PORT) + ")")
    a = pcap.loop(0,callback)  
      
def get_new_port(cmd_sut_port):
    new_port = last_new_ports.get(cmd_sut_port)
    return new_port  
     
def sniff_for_new_port(cmd_sut_port, wait_time):
    div = wait_time/10
    #print "sniffing for response ", wait_time
    for i in range(0,9):
        #print "waiting... ", div
        time.sleep(div)
        new_port = get_new_port(cmd_sut_port)     
        #self._received.wait(timeout=wait_time)
        #response = self.getLastCmdResponse(serverPort, senderPort)    
        #self._received.clear()
    return new_port  

def get_syn_packet(learner_port):
    last_syn_response = last_syn_responses.get(learner_port)
    return last_syn_response  
     
def sniff_for_syn_packet(learner_port, wait_time):
    div = wait_time/10
    #print "sniffing for response ", wait_time
    for i in range(0,9):
        #print "waiting... ", div
        time.sleep(div)
        syn_packet = get_syn_packet(learner_port)     
        #self._received.wait(timeout=wait_time)
        #response = self.getLastCmdResponse(serverPort, senderPort)    
        #self._received.clear()
    return syn_packet 
        
class PacketTrackerThread(threading.Thread):
    def __init__(self):
        super(PacketTrackerThread, self).__init__()

    def run(self):
        track_packets()  # 启动抓包功能                
def main():
    tracker_thread = PacketTrackerThread()
    tracker_thread.daemon = True  # 设置为守护线程，主程序退出时，线程也会退出
    tracker_thread.start()
    
    # 连接到服务器
    connect_to_server() #建立传输命令的socket
    new_port = sniff_for_new_port(SERVER_CMD_PORT, 0.6) #SUT端的实际交互的新通信端口
    print (new_port)
    #message = raw_input("connect")
    # send_message("connect")
    client_socket.send("connect\n")
    syn_packet = sniff_for_syn_packet(LEARNER_PORT, WAIT_TIME)
    
    rand_seq = random.randint(65536, 4294967295)
    rand_seq_unvalid = random.randint(65536, 4294967295)
    rand_ack_unvalid = random.randint(65536, 4294967295)
    if new_port == syn_packet[0]:
        '''
        syn_ack = ScapyIP(dst=SERVER_ADDR) / ScapyTCP(sport=syn_packet[1], dport=syn_packet[0], flags="SA", seq=rand_seq, ack=syn_packet[2] + 1)
        syn_ack_ack = sr1(syn_ack)
        # syn_valid = ScapyIP(dst=SERVER_ADDR) / ScapyTCP(sport=syn_packet[1], dport=syn_packet[0], flags="S", seq=syn_ack_ack.ack + 60000)
        # send(syn_valid)
        push_ack1 = ScapyIP(dst=SERVER_ADDR) / ScapyTCP(sport=syn_packet[1], dport=syn_packet[0], flags="PA", seq=syn_ack_ack.ack, ack=syn_ack_ack.seq)/Raw(b'\x01')
        ack1 = sr1(push_ack1)
        n = ceil((2 ** 32) / SERVER_WINDOWS)
        n = int(n)
        init_rand_seq = random.randint(0, SERVER_WINDOWS)
        for i in range(n):
            seq = init_rand_seq + i * SERVER_WINDOWS
            rst_unvalid = ScapyIP(dst=SERVER_ADDR) / ScapyTCP(sport=syn_packet[1], dport=syn_packet[0], flags="R", seq = seq)
            send(rst_unvalid)
        # rst_unvalid = ScapyIP(dst=SERVER_ADDR) / ScapyTCP(sport=syn_packet[1], dport=syn_packet[0], flags="R", seq=ack1.ack + 60000)
        # send(rst_unvalid)
        push_ack2 = ScapyIP(dst=SERVER_ADDR) / ScapyTCP(sport=syn_packet[1], dport=syn_packet[0], flags="PA", seq=ack1.ack, ack=ack1.seq)/Raw(b'\x01')
        send(push_ack2)
        '''

        rst_ack = ScapyIP(dst=SERVER_ADDR) / ScapyTCP(sport=syn_packet[1], dport=syn_packet[0], flags="RA", seq=rand_seq, ack=syn_packet[2] + 1)
        send(rst_ack)

        syn1_u = ScapyIP(dst=SERVER_ADDR) / ScapyTCP(sport=syn_packet[1], dport=syn_packet[0], flags="S", seq=rand_seq)

        syn1 = ScapyIP(dst=SERVER_ADDR) / ScapyTCP(sport=syn_packet[1], dport=syn_packet[0], flags="S", seq=rst_ack.seq)
        send(syn1_u)
        #send(syn1)
    print ("packets sending finished")
    
if __name__ == "__main__":
    main()


