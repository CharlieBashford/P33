#!/usr/bin/env python

from NFTest import *
import sys
import os
from scapy.layers.all import Ether, IP, TCP

phy2loop0 = ('../connections/2phy', [])

nftest_init(sim_loop = [], hw_config = [phy2loop0])

send_n_packets = 17

nftest_start()

routerMAC = []
routerIP = []
ethMAC = []
ethIP = []
pkts = []
xpkts = []
for i in range(4):
    routerMAC.append("00:4E:46:31:30:%d"%(i+7))
    routerIP.append("192.168.%s.40"%(200+i+7))
    ethMAC.append("00:0F:53:0D:D1:%d"%(78+i+7))
    ethIP.append("192.168.%s.40"%(100+i+7))
    pkt = make_IP_pkt(src_MAC=ethMAC[i], dst_MAC=routerMAC[i],
                      EtherType=0x800, src_IP=ethIP[i],
                      dst_IP=routerIP[i], xpkts_len=100+i)
    pkt.time = ((i*(1e-8)) + (1e-6))
    #pkt.tuser_sport = 1 << (i * 2);
    pkts.append(pkt)

if isHW() and 1:
    for i in range(send_n_packets):
	    nftest_send_phy('nf0', pkts[0])
	    nftest_expect_phy('nf1', pkts[0])
	    nftest_barrier()
    for i in range(send_n_packets):
	    nftest_send_phy('nf1', pkts[1])
	    nftest_expect_phy('nf0', pkts[1])
	    nftest_barrier()

if isHW() and 1:
    for i in range(send_n_packets):
	    nftest_send_dma('nf0', pkts[0])
	    nftest_expect_phy('nf0', pkts[0])
	    nftest_expect_phy('nf1', pkts[0])
	    nftest_barrier()
    for i in range(send_n_packets):
	    nftest_send_dma('nf1', pkts[1])
	    nftest_expect_phy('nf0', pkts[1])
	    nftest_expect_phy('nf1', pkts[1])
	    nftest_barrier()
    # Seems if there's no physical port in the connections file
    # the test framework does not like dma on it either:
    #
    #	Running test using the following physical connections:
    #	nf1:eth3
    #	nf0:eth2
    #	------------------------------------------------------
    #	Traceback (most recent call last):
    #	  File "/tmp/root/test/bir_starter/both_stage9_floodingsw/run.py", line 60, in <module>
    #	    nftest_send_dma('nf2', pkts[2])
    #	  File "/root/netfpga/HW_stub/NetFPGA-10G-live/lib/python/NFTest/NFTestLib.py", line 223, in nftest_send_dma
    #	    sent_dma[ifaceName].append(pkt)
    #	KeyError: 'nf2'
    if 0:
	    for i in range(send_n_packets):
		    nftest_send_dma('nf2', pkts[2])
		    nftest_expect_phy('nf0', pkts[2])
		    nftest_expect_phy('nf1', pkts[2])
		    nftest_barrier()
	    for i in range(send_n_packets):
		    nftest_send_dma('nf3', pkts[3])
		    nftest_expect_phy('nf0', pkts[3])
		    nftest_expect_phy('nf1', pkts[3])
		    nftest_barrier()

if not isHW() and 1:
    for i in range(send_n_packets):
        xpkts.append(pkts[0])
    nftest_send_phy('nf0', xpkts)
    nftest_expect_phy('nf1', xpkts)
    nftest_expect_phy('nf2', xpkts)
    nftest_expect_phy('nf3', xpkts)
    for i in range(send_n_packets):
        xpkts.remove(pkts[0])
    nftest_barrier()
    for i in range(send_n_packets):
        xpkts.append(pkts[1])
    nftest_send_phy('nf1', xpkts)
    nftest_expect_phy('nf0', xpkts)
    nftest_expect_phy('nf2', xpkts)
    nftest_expect_phy('nf3', xpkts)
    for i in range(send_n_packets):
        xpkts.remove(pkts[1])
    nftest_barrier()
    for i in range(send_n_packets):
        xpkts.append(pkts[2])
    nftest_send_phy('nf2', xpkts)
    nftest_expect_phy('nf0', xpkts)
    nftest_expect_phy('nf1', xpkts)
    nftest_expect_phy('nf3', xpkts)
    for i in range(send_n_packets):
        xpkts.remove(pkts[2])
    nftest_barrier()
    for i in range(send_n_packets):
        xpkts.append(pkts[3])
    nftest_send_phy('nf3', xpkts)
    nftest_expect_phy('nf0', xpkts)
    nftest_expect_phy('nf1', xpkts)
    nftest_expect_phy('nf2', xpkts)
    for i in range(send_n_packets):
        xpkts.remove(pkts[3])
    nftest_barrier()

if not isHW() and 1:
    for i in range(send_n_packets):
        xpkts.append(pkts[0])
    nftest_send_dma('nf0', xpkts)
    nftest_expect_phy('nf0', xpkts)
    nftest_expect_phy('nf1', xpkts)
    nftest_expect_phy('nf2', xpkts)
    nftest_expect_phy('nf3', xpkts)
    for i in range(send_n_packets):
        xpkts.remove(pkts[0])
    nftest_barrier()
    for i in range(send_n_packets):
        xpkts.append(pkts[1])
    nftest_send_dma('nf1', xpkts)
    nftest_expect_phy('nf0', xpkts)
    nftest_expect_phy('nf1', xpkts)
    nftest_expect_phy('nf2', xpkts)
    nftest_expect_phy('nf3', xpkts)
    for i in range(send_n_packets):
        xpkts.remove(pkts[1])
    nftest_barrier()
    for i in range(send_n_packets):
        xpkts.append(pkts[2])
    nftest_send_dma('nf2', xpkts)
    nftest_expect_phy('nf0', xpkts)
    nftest_expect_phy('nf1', xpkts)
    nftest_expect_phy('nf2', xpkts)
    nftest_expect_phy('nf3', xpkts)
    for i in range(send_n_packets):
        xpkts.remove(pkts[2])
    nftest_barrier()
    for i in range(send_n_packets):
        xpkts.append(pkts[3])
    nftest_send_dma('nf3', xpkts)
    nftest_expect_phy('nf0', xpkts)
    nftest_expect_phy('nf1', xpkts)
    nftest_expect_phy('nf2', xpkts)
    nftest_expect_phy('nf3', xpkts)
    for i in range(send_n_packets):
        xpkts.remove(pkts[3])

nftest_barrier()
mres=[]

nftest_finish(mres)
