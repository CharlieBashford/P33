#!/usr/bin/env python

from NFTest import *
import sys
import os
from scapy.layers.all import Ether, IP, TCP

phy2loop0 = ('../connections/2phy', [])

nftest_init(sim_loop = [], hw_config = [phy2loop0])

nftest_start()

routerMAC = []
routerIP = []
ethMAC = []
ethIP = []
for i in range(4):
    routerMAC.append("00:4E:46:31:30:%d"%(i+7))
    routerIP.append("192.168.%s.40"%(200+i+7))
    ethMAC.append("00:0F:53:0D:D1:%d"%(78+i+7))
    ethIP.append("192.168.%s.40"%(100+i+7))

num_broadcast = 17

pkts = []
for i in range(num_broadcast):
    pkt = make_IP_pkt(src_MAC=ethMAC[0], dst_MAC=routerMAC[0],
                      EtherType=0x800, src_IP=ethIP[0],
                      dst_IP=routerIP[0], pkt_len=100+i)
    pkt.time = ((i*(1e-8)) + (1e-6))
    pkts.append(pkt)
    if isHW() and 1:
	nftest_send_phy('nf0', pkt)
	nftest_expect_phy('nf1', pkt)
        nftest_barrier()

if isHW() and 1:
	for i in range(num_broadcast):
	    pkt = make_IP_pkt(src_MAC=ethMAC[1], dst_MAC=routerMAC[1],
			      EtherType=0x800, src_IP=ethIP[1],
			      dst_IP=routerIP[1], pkt_len=100+i)
	    pkt.time = ((i*(1e-8)) + (1e-6))
	    nftest_send_phy('nf1', pkt)
	    nftest_expect_phy('nf1', pkt)
	    nftest_barrier()

if not isHW() and 1:
    nftest_send_phy('nf0', pkts)
    nftest_expect_phy('nf1', pkts)
    nftest_barrier()
    nftest_send_phy('nf1', pkts)
    nftest_expect_phy('nf1', pkts)
    nftest_barrier()
    nftest_send_phy('nf2', pkts)
    nftest_expect_phy('nf1', pkts)
    nftest_barrier()
    nftest_send_phy('nf3', pkts)
    nftest_expect_phy('nf1', pkts)
    nftest_barrier()

if not isHW() and 1:
    nftest_send_dma('nf0', pkts)
    nftest_expect_phy('nf1', pkts)
    nftest_barrier()
    nftest_send_dma('nf1', pkts)
    nftest_expect_phy('nf1', pkts)
    nftest_barrier()
    nftest_send_dma('nf2', pkts)
    nftest_expect_phy('nf1', pkts)
    nftest_barrier()
    nftest_send_dma('nf3', pkts)
    nftest_expect_phy('nf1', pkts)

nftest_barrier()
mres=[]

nftest_finish(mres)
