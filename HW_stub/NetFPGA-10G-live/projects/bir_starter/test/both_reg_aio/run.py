#!/usr/bin/env python

from reg_defines_reference_router import *
from NFTest import *
import sys
import os
from scapy.layers.all import Ether, IP, TCP

phy2loop0 = ('../connections/2phy', [])

baseaddr = 0x76800000;
send_n_packets = 1
xpkts = []

# ARP request
apkt = make_ARP_request_pkt(src_MAC="00:0F:53:0D:D1:01", dst_MAC="ff:ff:ff:ff:ff:ff",
			EtherType=0x0806,
			src_IP="192.0.2.1", dst_IP="255.255.255.255");
apkt.time = (1 * (1e-8) + (1e-6))

# IP packet
ipkt = make_IP_pkt(src_MAC="00:0F:53:0D:D1:01", dst_MAC="00:0F:53:0D:D1:02",
			EtherType=0x0800,
			src_IP="192.0.2.1", dst_IP="192.0.2.2",
			pkts_len = 102);
ipkt.time = (4 * (1e-8) + (1e-6))

# IP, OSPF proto
opkt = make_IP_pkt(src_MAC="00:0F:53:0D:D1:01", dst_MAC="01:00:5E:00:00:05",
			EtherType=0x0800,
			src_IP="192.0.2.1", dst_IP="224.0.0.5",
			pkts_len = 103);
opkt[IP].proto = 89;
opkt.time = (8 * (1e-8) + (1e-6))

apkt.show()
ipkt.show()
opkt.show()

nftest_init(sim_loop = [], hw_config = [phy2loop0])
nftest_start()

# Clear registers
nftest_regwrite(baseaddr, 1)
nftest_regwrite(baseaddr, 0)
nftest_barrier()

# Program ethernet addresses
# assign mac_0 = rw_regs[MAC_WIDTH - 1 + C_S_AXI_DATA_WIDTH*MAC0_OFFSET:C_S_AXI_DATA_WIDTH*MAC0_OFFSET];
nftest_regwrite(      XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_MAC_0_HIGH(), 0x00006055)
nftest_regwrite(      XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_MAC_0_LOW(),  0x44332210)
nftest_regwrite(      XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_MAC_1_HIGH(), 0x00006055)
nftest_regwrite(      XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_MAC_1_LOW(),  0x44332211)
nftest_regwrite(      XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_MAC_2_HIGH(), 0x00006055)
nftest_regwrite(      XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_MAC_2_LOW(),  0x44332212)
nftest_regwrite(      XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_MAC_3_HIGH(), 0x00006055)
nftest_regwrite(      XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_MAC_3_LOW(),  0x44332213)
nftest_barrier()
nftest_regread_expect(XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_MAC_0_HIGH(), 0x00006055)
nftest_regread_expect(XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_MAC_0_LOW(),  0x44332210)
nftest_regread_expect(XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_MAC_1_HIGH(), 0x00006055)
nftest_regread_expect(XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_MAC_1_LOW(),  0x44332211)
nftest_regread_expect(XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_MAC_2_HIGH(), 0x00006055)
nftest_regread_expect(XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_MAC_2_LOW(),  0x44332212)
nftest_regread_expect(XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_MAC_3_HIGH(), 0x00006055)
nftest_regread_expect(XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_MAC_3_LOW(),  0x44332213)
nftest_barrier()


if isHW() and 1:
    for i in range(send_n_packets):
	    nftest_send_phy('nf0', apkt)
	    nftest_expect_phy('nf1', apkt)
	    nftest_barrier()
	    nftest_send_phy('nf0', ipkt)
	    nftest_expect_phy('nf1', ipkt)
	    nftest_barrier()
	    nftest_send_phy('nf0', opkt)
	    nftest_expect_phy('nf1', opkt)
	    nftest_barrier()

if not isHW() and 1:
    for i in range(send_n_packets):
        xpkts.append(apkt)
    nftest_send_phy('nf0', xpkts)
    nftest_expect_phy('nf1', xpkts)
    nftest_expect_phy('nf2', xpkts)
    nftest_expect_phy('nf3', xpkts)
    for i in range(send_n_packets):
        xpkts.remove(apkt)
    nftest_barrier()
    nftest_regread_expect(XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_PKT_ARP(), send_n_packets)	# ARP
    nftest_regread_expect(XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_PKT_IP(), 0)			# IPv4
    nftest_regread_expect(XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_PKT_OSPF(), 0)			# OSPF
    
    for i in range(send_n_packets):
        xpkts.append(ipkt)
    nftest_send_phy('nf0', xpkts)
    nftest_expect_phy('nf1', xpkts)
    nftest_expect_phy('nf2', xpkts)
    nftest_expect_phy('nf3', xpkts)
    for i in range(send_n_packets):
        xpkts.remove(ipkt)
    nftest_barrier()
    nftest_regread_expect(XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_PKT_ARP(), send_n_packets)	# ARP
    nftest_regread_expect(XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_PKT_IP(), send_n_packets)	# IPv4
    nftest_regread_expect(XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_PKT_OSPF(), 0)			# OSPF
    
    for i in range(send_n_packets):
        xpkts.append(opkt)
    nftest_send_phy('nf0', xpkts)
    nftest_expect_phy('nf1', xpkts)
    nftest_expect_phy('nf2', xpkts)
    nftest_expect_phy('nf3', xpkts)
    for i in range(send_n_packets):
        xpkts.remove(opkt)
    nftest_barrier()
    nftest_regread_expect(XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_PKT_ARP(), send_n_packets)	# ARP
    nftest_regread_expect(XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_PKT_IP(), send_n_packets)	# IPv4
    nftest_regread_expect(XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_PKT_OSPF(), send_n_packets)	# OSPF

if not isHW() and 1:
    for i in range(send_n_packets):
        xpkts.append(apkt)
        xpkts.append(ipkt)
        xpkts.append(opkt)
    nftest_send_dma('nf0', xpkts)
    nftest_expect_phy('nf0', xpkts)
    nftest_expect_phy('nf1', xpkts)
    nftest_expect_phy('nf2', xpkts)
    nftest_expect_phy('nf3', xpkts)
    for i in range(send_n_packets):
        xpkts.remove(opkt)
        xpkts.remove(ipkt)
        xpkts.remove(apkt)
    nftest_barrier()
    nftest_regread_expect(XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_PKT_ARP(), 2 * send_n_packets)	# ARP
    nftest_regread_expect(XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_PKT_IP(), 2 * send_n_packets)	# IPv4
    nftest_regread_expect(XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_PKT_OSPF(), 2 * send_n_packets)	# OSPF

nftest_barrier()
mres=[]

nftest_finish(mres)
