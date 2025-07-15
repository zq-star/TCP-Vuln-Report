# -*- coding: utf-8 -*-
from scapy.all import *
import random
import time

# 配置目标信息
target_ip = "192.168.1.5"  # 目标 IP 地址 AT-76, HW-24, Simens-400-40, simens-smart200-200, TD-5, Simens-1200-120
target_port = 502  # 目标端口
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

# 步骤 2: 发送 FIN_ACK1_v 包
fin_ack1_v = IP(dst=target_ip) / TCP(sport=src_port, dport=target_port, flags="FA", seq=syn_ack.ack, ack=syn_ack.seq + 1)
send(fin_ack1_v)  # 发送 ACK

print("[*] 发送 FIN_ACK1_v")

# 步骤 3: 发送 ACK_v 包
ack2_v = IP(dst=target_ip) / TCP(sport=src_port, dport=target_port, flags="A", seq=fin_ack1_v.seq, ack=fin_ack1_v.ack)
send(ack2_v)  # 发送 ACK_v

print("[*] 发送 ACK_v")

# 步骤 4: 发送 包
syn2_v = IP(dst=target_ip) / TCP(sport=src_port, dport=target_port, flags="S", seq=ack2_v.seq, ack=ack2_v.ack)
syn2_i = IP(dst=target_ip) / TCP(sport=src_port, dport=target_port, flags="S", seq=ack2_v.seq + 321, ack=rand_ack)
send(syn2_i)  # 发送 syn2-v 包
#send(syn2_i)  # 发送 syn2-i 包
