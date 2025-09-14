# -*- coding: utf-8 -*-
from scapy.all import *
import random
import time

# 配置目标信息
target_ip = "192.168.1.201"  # 目标 IP 地址 AT-76, HW-24, Simens-400-40, simens-smart200-200, TD-5, Simens-1200-120
target_port = 102  # 目标端口
windows = 65536

# 生成一个随机的源端口
src_port = random.randint(1024, 65535)
init_seq = random.randint(0, 2**32 - 1)
rand_seq = random.randint(0, 2**32 - 1)
rand_ack = random.randint(0, 2**32 - 1)

# 步骤 1: 发送 SYN1_v 包，开始建立连接
syn1_v = IP(dst=target_ip) / TCP(sport=src_port, dport=target_port, flags="S", seq=init_seq)
syn_ack = sr1(syn1_v)  # 发送 SYN 并等待回应 SYN+ACK

print("[*] 发送 SYN1_v，接收到回应 SYN+ACK")

# 步骤 2: 发送 RST1_i 包
rst1_i = IP(dst=target_ip) / TCP(sport=src_port, dport=target_port, flags="R", seq=syn_ack.ack+200)
send(rst1_i)  # 发送 RST1_i

print("[*] 发送 RST1_i")

# 步骤 3: 发送 RST2_i 包
rst2_i = IP(dst=target_ip) / TCP(sport=src_port, dport=target_port, flags="R", seq=syn_ack.ack+100)
send(rst2_i)  # 发送 RST2_i

print("[*] 发送 RST2_i")

# 步骤 3: 发送包
syn2_i = IP(dst=target_ip) / TCP(sport=src_port, dport=target_port, flags="S", seq=rand_seq)
#send(syn2_v)  
send(syn2_i) 
