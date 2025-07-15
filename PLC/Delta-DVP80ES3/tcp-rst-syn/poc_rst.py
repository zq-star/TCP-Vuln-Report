# -*- coding: utf-8 -*-
from scapy.all import *
import random
import time

# 配置目标信息
target_ip = "192.168.1.5"  # 目标 IP 地址
target_port = 502  # 目标端口
windows = 65536

# 生成一个随机的源端口
src_port = random.randint(1024, 65535)
init_seq = random.randint(0, 2**32 - 1)
rand_seq = random.randint(0, 2**32 - 1)

# 步骤 1: 发送 SYN 包，开始建立连接
syn = IP(dst=target_ip) / TCP(sport=src_port, dport=target_port, flags="S", seq=init_seq)
syn_ack = sr1(syn)  # 发送 SYN 并等待回应 SYN+ACK

print("[*] 发送 SYN，接收到回应 SYN+ACK")

# 步骤 2: 发送 ACK 包，完成 TCP 握手
syn_ack_ack = IP(dst=target_ip) / TCP(sport=src_port, dport=target_port, flags="A", seq=syn_ack.ack, ack=syn_ack.seq + 1)
send(syn_ack_ack)  # 发送 SYN+ACK

print("[*] 发送 SYN+ACK，完成 TCP 握手")

# 步骤 3: 发送 ACK1 包
ack1 = IP(dst=target_ip) / TCP(sport=src_port, dport=target_port, flags="A", seq=syn_ack_ack.seq, ack=syn_ack_ack.ack)
send(ack1)  # 发送 RST 包以重置连接

# 步骤 4: 发送 RST 包，重置连接
# rst = IP(dst=target_ip) / TCP(sport=src_port, dport=target_port, flags="R", seq=syn_ack_ack.seq + windows + 6000)
# rst = IP(dst=target_ip) / TCP(sport=src_port, dport=target_port, flags="R", seq=syn_ack_ack.seq + 6000)
rst = IP(dst=target_ip) / TCP(sport=src_port, dport=target_port, flags="R", seq=rand_seq)
send(rst)  # 发送 RST 包以重置连接

print("[*] 发送 RST 包，重置连接")

# 步骤 5: 发送 ACK2 包，确认连接断开
ack2 = IP(dst=target_ip) / TCP(sport=src_port, dport=target_port, flags="A", seq=syn_ack_ack.seq, ack=syn_ack_ack.ack)
send(ack2)  # 发送 ACK 包确认连接关闭

print("[*] 发送 ACK2 包，连接断开")
