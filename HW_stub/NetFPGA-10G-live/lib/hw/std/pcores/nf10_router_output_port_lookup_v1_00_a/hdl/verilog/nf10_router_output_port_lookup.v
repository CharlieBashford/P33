/*******************************************************************************
 *
 *  NetFPGA-10G http://www.netfpga.org
 *
 *  File:
 *        nf10_output_port_lookup.v
 *
 *  Library:
 *        hw/std/pcores/nf10_router_output_port_lookup_v1_00_a
 *
 *  Module:
 *        nf10_output_port_lookup
 *
 *  Author:
 *        Adam Covington, Gianni Antichi
 *
 *  Description:
 *        Hardwire the hardware interfaces to CPU and vice versa
 *
 *  Copyright notice:
 *        Copyright (C) 2010, 2011 The Board of Trustees of The Leland Stanford
 *                                 Junior University
 *	  Copyright (c) 2014, Bjoern A. Zeeb
 *	  All rights reserved.
 *
 *  Licence:
 *        This file is part of the NetFPGA 10G development base package.
 *
 *        This file is free code: you can redistribute it and/or modify it under
 *        the terms of the GNU Lesser General Public License version 2.1 as
 *        published by the Free Software Foundation.
 *
 *        This package is distributed in the hope that it will be useful, but
 *        WITHOUT ANY WARRANTY; without even the implied warranty of
 *        MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *        Lesser General Public License for more details.
 *
 *        You should have received a copy of the GNU Lesser General Public
 *        License along with the NetFPGA source package.  If not, see
 *        http://www.gnu.org/licenses/.
 *
 */

module nf10_router_output_port_lookup
	#(
		parameter C_FAMILY = "virtex5",
		parameter C_S_AXI_DATA_WIDTH = 32,
		parameter C_S_AXI_ADDR_WIDTH = 32,
		parameter C_USE_WSTRB = 0,
		parameter C_DPHASE_TIMEOUT = 0,
		parameter C_S_AXI_ACLK_FREQ_HZ = 100,
		parameter C_BAR0_BASEADDR = 32'h76800000,
		parameter C_BAR0_HIGHADDR = 32'h76800FFF,
		parameter C_BAR1_BASEADDR = 32'h74800000,
		parameter C_BAR1_HIGHADDR = 32'h7480FFFF,
		//Master AXI Stream Data Width
		parameter C_M_AXIS_DATA_WIDTH=256,
		parameter C_S_AXIS_DATA_WIDTH=256,
		parameter C_M_AXIS_TUSER_WIDTH=128,
		parameter C_S_AXIS_TUSER_WIDTH=128,
		parameter SRC_PORT_POS=16,
		parameter DST_PORT_POS=24
	)
	// inputs and outputs
	(
		// Global Ports
		input					AXI_ACLK,
		input					AXI_RESETN,

		// Slave Stream Ports (interface from RX queues)
		input [C_S_AXIS_DATA_WIDTH-1:0] 	S_AXIS_TDATA,
		input [((C_S_AXIS_DATA_WIDTH/8))-1:0]	S_AXIS_TSTRB,
		input [C_S_AXIS_TUSER_WIDTH-1:0] 	S_AXIS_TUSER,
		input					S_AXIS_TVALID,
		input					S_AXIS_TLAST,
		output					S_AXIS_TREADY,

		// Master Stream Ports (interface to TX data path)
		input					M_AXIS_TREADY,
		output [C_M_AXIS_DATA_WIDTH-1:0] 	M_AXIS_TDATA,
		output [((C_M_AXIS_DATA_WIDTH/8))-1:0]	M_AXIS_TSTRB,
		output [C_M_AXIS_TUSER_WIDTH-1:0]	M_AXIS_TUSER,
		output					M_AXIS_TVALID,
		output					M_AXIS_TLAST,

		// Register port definitions.
		input [C_S_AXI_ADDR_WIDTH-1:0]		S_AXI_AWADDR,
		input					S_AXI_AWVALID,
		input [C_S_AXI_DATA_WIDTH-1:0]		S_AXI_WDATA,
		input [C_S_AXI_DATA_WIDTH/8-1:0]	S_AXI_WSTRB,
		input					S_AXI_WVALID,
		input					S_AXI_BREADY,
		input [C_S_AXI_ADDR_WIDTH-1:0]		S_AXI_ARADDR,
		input					S_AXI_ARVALID,
		input					S_AXI_RREADY,
		output					S_AXI_ARREADY,
		output [C_S_AXI_DATA_WIDTH-1:0]		S_AXI_RDATA,
		output [1:0]				S_AXI_RRESP,
		output					S_AXI_RVALID,
		output					S_AXI_WREADY,
		output [1:0]				S_AXI_BRESP,
		output					S_AXI_BVALID,
		output					S_AXI_AWREADY
	);


	// ---------------------------------------------------------------------
	// Helper function
	function integer log2;
		input integer number;
	begin
		log2=0;
		while(2**log2<number) begin
			log2=log2+1;
		end
	end
	endfunction // log2

	// ---------------------------------------------------------------------
	// Bus wiring.
	wire					Bus2IP_Clk;
	wire					Bus2IP_Resetn;
	wire [C_S_AXI_ADDR_WIDTH-1:0]		Bus2IP_Addr;
	wire [1:0]				Bus2IP_CS;
	wire					Bus2IP_RNW;
	wire [C_S_AXI_DATA_WIDTH-1:0]		Bus2IP_Data;
	wire [C_S_AXI_DATA_WIDTH/8-1:0]		Bus2IP_BE;
	// We need to multiplex these in order to use them with
	// the registers and all four tables.  I hate hardware.
	// Try to do c/f to Gianni's osnt_monitoring_output_port_lookup sample.
	reg [C_S_AXI_DATA_WIDTH-1:0]		IP2Bus_Data;
	reg					IP2Bus_RdAck;
	reg					IP2Bus_WrAck;
	reg					IP2Bus_Error;
	// This double-array syntax drives me nuts.
	wire [C_S_AXI_DATA_WIDTH-1:0]		mp_IP2Bus_Data [0:3];
	wire [3:0]				mp_IP2Bus_RdAck;
	wire [3:0]				mp_IP2Bus_WrAck;
	wire [3:0]				mp_IP2Bus_Error;

	// ---------------------------------------------------------------------
	// Clockwork:
	// do the multi-plexing.
  	always @ (posedge Bus2IP_Clk) begin
		case (mp_IP2Bus_RdAck)
			4'b0001: IP2Bus_Data <= mp_IP2Bus_Data[0];
			4'b0010: IP2Bus_Data <= mp_IP2Bus_Data[1];
			4'b0100: IP2Bus_Data <= mp_IP2Bus_Data[2];
			4'b1000: IP2Bus_Data <= mp_IP2Bus_Data[3];
			default: IP2Bus_Data <= {C_S_AXI_DATA_WIDTH{1'b0}};
		endcase

		IP2Bus_WrAck <= |mp_IP2Bus_WrAck;
		IP2Bus_RdAck <= |mp_IP2Bus_RdAck;
		IP2Bus_Error <= |mp_IP2Bus_Error;
	end

	// ---------------------------------------------------------------------
	// AXI-to-Register/Table mapping thingy (technical term:)
	// -- AXILITE IPIF
	axi_lite_ipif_2bars #
	(
		.C_S_AXI_DATA_WIDTH	(C_S_AXI_DATA_WIDTH),
		.C_S_AXI_ADDR_WIDTH	(C_S_AXI_ADDR_WIDTH),
		.C_USE_WSTRB		(C_USE_WSTRB),
		.C_DPHASE_TIMEOUT	(C_DPHASE_TIMEOUT),
		.C_BAR0_BASEADDR	(C_BAR0_BASEADDR),
		.C_BAR0_HIGHADDR	(C_BAR0_HIGHADDR),
		.C_BAR1_BASEADDR	(C_BAR1_BASEADDR),
		.C_BAR1_HIGHADDR	(C_BAR1_HIGHADDR)
	) axi_lite_ipif_inst
	(
		.S_AXI_ACLK		( AXI_ACLK ),
		.S_AXI_ARESETN		( AXI_RESETN ),
		.S_AXI_AWADDR		( S_AXI_AWADDR ),
		.S_AXI_AWVALID		( S_AXI_AWVALID ),
		.S_AXI_WDATA		( S_AXI_WDATA ),
		.S_AXI_WSTRB		( S_AXI_WSTRB ),
		.S_AXI_WVALID		( S_AXI_WVALID ),
		.S_AXI_BREADY		( S_AXI_BREADY ),
		.S_AXI_ARADDR		( S_AXI_ARADDR ),
		.S_AXI_ARVALID		( S_AXI_ARVALID ),
		.S_AXI_RREADY		( S_AXI_RREADY ),
		.S_AXI_ARREADY		( S_AXI_ARREADY ),
		.S_AXI_RDATA		( S_AXI_RDATA ),
		.S_AXI_RRESP		( S_AXI_RRESP ),
		.S_AXI_RVALID		( S_AXI_RVALID ),
		.S_AXI_WREADY		( S_AXI_WREADY ),
		.S_AXI_BRESP		( S_AXI_BRESP ),
		.S_AXI_BVALID		( S_AXI_BVALID ),
		.S_AXI_AWREADY		( S_AXI_AWREADY ),

		// Controls to the IP/IPIF modules
		.Bus2IP_Clk		( Bus2IP_Clk ),
		.Bus2IP_Resetn		( Bus2IP_Resetn ),
		.Bus2IP_Addr		( Bus2IP_Addr ),
		.Bus2IP_RNW		( Bus2IP_RNW ),
		.Bus2IP_BE		( Bus2IP_BE ),
		.Bus2IP_CS		( Bus2IP_CS ),
		.Bus2IP_Data		( Bus2IP_Data ),
		.IP2Bus_Data		( IP2Bus_Data ),
		.IP2Bus_WrAck		( IP2Bus_WrAck ),
		.IP2Bus_RdAck		( IP2Bus_RdAck ),
		.IP2Bus_Error		( IP2Bus_Error )
	);
  
	// ---------------------------------------------------------------------
	// Registers (counters and mac)

	// ---------------------------------------------------------------------
	// Local definitions:
	// clear + 4 x ether address (which need 2 regs each)
	localparam	NUM_RW_REGS		= 1 + 4 * 2;
	localparam	NUM_RO_REGS		= 13;

	localparam	MAC_WIDTH		= 48;

	localparam	COUNTER_ZERO_ALL_OFFSET	= 0;
	localparam	MAC0_OFFSET		= 1;
	localparam	MAC1_OFFSET		= 3;
	localparam	MAC2_OFFSET		= 5;
	localparam	MAC3_OFFSET		= 7;
	localparam	RO_REGS_OFFSET		= 9;

	// --------------------------------------------------------------------------
	// Stats registers (10(+3) readbale for stats counters)
	reg [C_S_AXI_DATA_WIDTH-1:0]		r_counter_pkts_eth_bad_dst;
	reg [C_S_AXI_DATA_WIDTH-1:0]		r_counter_pkts_not_ip4;
	reg [C_S_AXI_DATA_WIDTH-1:0]		r_counter_pkts_to_cpu;
	reg [C_S_AXI_DATA_WIDTH-1:0]		r_counter_pkts_ip4_options;
	reg [C_S_AXI_DATA_WIDTH-1:0]		r_counter_pkts_ip4_bad_csum;
	reg [C_S_AXI_DATA_WIDTH-1:0]		r_counter_pkts_ip4_bad_ttl;
	reg [C_S_AXI_DATA_WIDTH-1:0]		r_counter_pkts_ip4_fwd;
	reg [C_S_AXI_DATA_WIDTH-1:0]		r_counter_pkts_ip4_local;
	reg [C_S_AXI_DATA_WIDTH-1:0]		r_counter_lpm_misses;
	reg [C_S_AXI_DATA_WIDTH-1:0]		r_counter_arp_misses;
	// +3 for initial assignment (keep the regs for tests to still work)
	// apart from reset `ifdefs are taking care that they are not touched.
	reg [C_S_AXI_DATA_WIDTH-1:0]		r_counter_pkts_arp;
	reg [C_S_AXI_DATA_WIDTH-1:0]		r_counter_pkts_ip4;
	reg [C_S_AXI_DATA_WIDTH-1:0]		r_counter_pkts_ospf;

	// Wires
	wire [NUM_RW_REGS * C_S_AXI_DATA_WIDTH-1:0]	rw_regs;
	wire [NUM_RO_REGS * C_S_AXI_DATA_WIDTH-1:0]	ro_regs;
	wire [MAC_WIDTH-1:0]				mac_0;
	wire [MAC_WIDTH-1:0]				mac_1;
	wire [MAC_WIDTH-1:0]				mac_2;
	wire [MAC_WIDTH-1:0]				mac_3;

	// Spaghetti
	// rw_regs
	assign counter_zero_all	= rw_regs[C_S_AXI_DATA_WIDTH * COUNTER_ZERO_ALL_OFFSET];
	assign mac_0		= rw_regs[MAC_WIDTH - 1 + C_S_AXI_DATA_WIDTH*MAC0_OFFSET:C_S_AXI_DATA_WIDTH*MAC0_OFFSET];
	assign mac_1		= rw_regs[MAC_WIDTH - 1 + C_S_AXI_DATA_WIDTH*MAC1_OFFSET:C_S_AXI_DATA_WIDTH*MAC1_OFFSET];
	assign mac_2		= rw_regs[MAC_WIDTH - 1 + C_S_AXI_DATA_WIDTH*MAC2_OFFSET:C_S_AXI_DATA_WIDTH*MAC2_OFFSET];
	assign mac_3		= rw_regs[MAC_WIDTH - 1 + C_S_AXI_DATA_WIDTH*MAC3_OFFSET:C_S_AXI_DATA_WIDTH*MAC3_OFFSET];
	// ro_regs (baseaddr + 10; reverse order!)
	assign ro_regs		= {
		// OSPF packet received
		r_counter_pkts_ospf,
		// IPv4 packets received
		r_counter_pkts_ip4,
		// ARP packet received
		r_counter_pkts_arp,
		// +3
		// -----------------------------------------------------
		// Packets sent to the CPU/software
		r_counter_pkts_to_cpu,
		// Packets with IP options
		r_counter_pkts_ip4_options,
		// Packets with bad TTLs
		r_counter_pkts_ip4_bad_ttl,
		// Packets sent to CPU matching one of the addresses in the local IP address
		// table (register name is filtered)
		r_counter_pkts_ip4_local,
		// Packets forwarded by the router (not sent to CPU)
		r_counter_pkts_ip4_fwd,
		// Packets with bad IP checksums
		r_counter_pkts_ip4_bad_csum,
		// Non-IP packet received  (means non-IPv4 really)
		r_counter_pkts_not_ip4,
		// ARP misses
		r_counter_arp_misses,
		// LPM misses
		r_counter_lpm_misses,
		// Packets with a bad Ethernet destination address
		r_counter_pkts_eth_bad_dst
		};

	// ---------------------------------------------------------------------
	// Registers
	ipif_regs #
	(
		.C_S_AXI_DATA_WIDTH	(C_S_AXI_DATA_WIDTH),          
		.C_S_AXI_ADDR_WIDTH	(C_S_AXI_ADDR_WIDTH),   
		.NUM_RW_REGS		(NUM_RW_REGS),
		.NUM_RO_REGS		(NUM_RO_REGS)
	) ipif_regs_inst
	(   
		.Bus2IP_Clk	( Bus2IP_Clk ),
		.Bus2IP_Resetn	( Bus2IP_Resetn ), 
		.Bus2IP_Addr	( Bus2IP_Addr ),
		.Bus2IP_CS	( Bus2IP_CS[1] ),	// BAR0
		.Bus2IP_RNW	( Bus2IP_RNW ),
		.Bus2IP_Data	( Bus2IP_Data ),
		.Bus2IP_BE	( Bus2IP_BE ),
		.IP2Bus_Data	( mp_IP2Bus_Data[0] ),
		.IP2Bus_RdAck	( mp_IP2Bus_RdAck[0] ),
		.IP2Bus_WrAck	( mp_IP2Bus_WrAck[0] ),
		.IP2Bus_Error	( mp_IP2Bus_Error[0] ),

		.rw_regs	( rw_regs ),
		.ro_regs	( ro_regs )
	);


	// ---------------------------------------------------------------------
	// Table layout in our address space:
	// (this is not what I thought it would be; we do not map them to the
	// outer world 1:1).
	// Still with the right offsets in mpd file this should work fine.
	//
	// 76801000		Low
	// 76801000 - 76801fff	Local IPv4 table	& 0xff00 == 0x0000
	// 76804000 - 76805fff	ARP			& 0xff00 == 0x0100
	// 76808000 - 7680bfff	FIB			& 0xff00 == 0x8000
	// 7680ffff		High


	// ---------------------------------------------------------------------
	// Local IPv4 table
	// ---------------------------------------------------------------------

	// ---------------------------------------------------------------------
	// Local definitions:
	localparam	IPV4_LOCAL_LUT_COLS	= 1;
	localparam	IPV4_LOCAL_LUT_ROWS	= 32;
	localparam	IPV4_LOCAL_LUT_ROW_BITS	= log2(IPV4_LOCAL_LUT_ROWS);

	// Wires:
	wire					ipv4_local_lut_rd_req;
	wire					ipv4_local_lut_rd_ack;
	wire [IPV4_LOCAL_LUT_ROW_BITS-1:0]	ipv4_local_lut_rd_addr;
	wire [31:0]				ipv4_local_lut_rd_ipv4_addr;
	wire					ipv4_local_lut_wr_req;
	wire					ipv4_local_lut_wr_ack;
	wire [IPV4_LOCAL_LUT_ROW_BITS-1:0]	ipv4_local_lut_wr_addr;
	wire [31:0]				ipv4_local_lut_wr_ipv4_addr;

	// ---------------------------------------------------------------------
	// Local IPv4 lookup table.
	ipif_table_regs
	#(
		.C_S_AXI_DATA_WIDTH	(C_S_AXI_DATA_WIDTH),
		.C_S_AXI_ADDR_WIDTH	(C_S_AXI_ADDR_WIDTH),
		.TBL_NUM_COLS		(IPV4_LOCAL_LUT_COLS),
		.TBL_NUM_ROWS		(IPV4_LOCAL_LUT_ROWS)
	) ipv4_local_lut_ipif_table_regs_inst
	// inputs and outputs
	(
		.Bus2IP_Clk	( Bus2IP_Clk ),
		.Bus2IP_Resetn	( Bus2IP_Resetn ),
		.Bus2IP_Addr	( Bus2IP_Addr ),
				// BAR1 & Local IPv4 table
		.Bus2IP_CS	( Bus2IP_CS[0] & (Bus2IP_Addr[15:8] == 8'h10)),
		.Bus2IP_RNW	( Bus2IP_RNW ),
		.Bus2IP_Data	( Bus2IP_Data ),
		.Bus2IP_BE	( Bus2IP_BE ),
		.IP2Bus_Data	( mp_IP2Bus_Data[3] ),
		.IP2Bus_RdAck	( mp_IP2Bus_RdAck[3] ),
		.IP2Bus_WrAck	( mp_IP2Bus_WrAck[3] ),
		.IP2Bus_Error	( mp_IP2Bus_Error[3] ),

		.tbl_rd_req	( ipv4_local_lut_rd_req ),
		.tbl_rd_ack	( ipv4_local_lut_rd_ack ),
		.tbl_rd_addr	( ipv4_local_lut_rd_addr ),
		.tbl_rd_data	( ipv4_local_lut_rd_ipv4_addr ),
		.tbl_wr_req	( ipv4_local_lut_wr_req ),
		.tbl_wr_ack	( ipv4_local_lut_wr_ack ),
		.tbl_wr_addr	( ipv4_local_lut_wr_addr ),
		.tbl_wr_data	( ipv4_local_lut_wr_ipv4_addr )
	);


	// ---------------------------------------------------------------------
	// FIB table
	// ---------------------------------------------------------------------

	// ---------------------------------------------------------------------
	// Local definitions:
	localparam	IPV4_FIB_LUT_COLS	= 4;
	localparam	IPV4_FIB_LUT_ROWS	= 32;
	localparam	IPV4_FIB_LUT_ROW_BITS	= log2(IPV4_FIB_LUT_ROWS);

	// Wires:
	wire					ipv4_fib_lut_rd_req;
	wire					ipv4_fib_lut_rd_ack;
	wire [IPV4_FIB_LUT_ROW_BITS-1:0]	ipv4_fib_lut_rd_addr;
	wire [7:0]				ipv4_fib_lut_rd_ipv4_oif;
	wire [31:0]				ipv4_fib_lut_rd_ipv4_nh;
	wire [31:0]				ipv4_fib_lut_rd_ipv4_mask;
	wire [31:0]				ipv4_fib_lut_rd_ipv4_net;
	wire					ipv4_fib_lut_wr_req;
	wire					ipv4_fib_lut_wr_ack;
	wire [IPV4_FIB_LUT_ROW_BITS-1:0]	ipv4_fib_lut_wr_addr;
	//wire [7:0]				ipv4_fib_lut_wr_ipv4_oif;
	wire [31:0]				ipv4_fib_lut_wr_ipv4_oif;
	wire [31:0]				ipv4_fib_lut_wr_ipv4_nh;
	wire [31:0]				ipv4_fib_lut_wr_ipv4_mask;
	wire [31:0]				ipv4_fib_lut_wr_ipv4_net;

	// ---------------------------------------------------------------------
	// FIB lookup table.
	ipif_table_regs
	#(
		.C_S_AXI_DATA_WIDTH	(C_S_AXI_DATA_WIDTH),
		.C_S_AXI_ADDR_WIDTH	(C_S_AXI_ADDR_WIDTH),
		.TBL_NUM_COLS		(IPV4_FIB_LUT_COLS),
		.TBL_NUM_ROWS		(IPV4_FIB_LUT_ROWS)
	) ipv4_fib_lut_ipif_table_regs_inst
	// inputs and outputs
	(
		.Bus2IP_Clk	( Bus2IP_Clk ),
		.Bus2IP_Resetn	( Bus2IP_Resetn ),
		.Bus2IP_Addr	( Bus2IP_Addr ),
				// BAR1 & FIB table
		.Bus2IP_CS	( Bus2IP_CS[0] & (Bus2IP_Addr[15:8] == 8'h80)),
		.Bus2IP_RNW	( Bus2IP_RNW ),
		.Bus2IP_Data	( Bus2IP_Data ),
		.Bus2IP_BE	( Bus2IP_BE ),
		.IP2Bus_Data	( mp_IP2Bus_Data[1] ),
		.IP2Bus_RdAck	( mp_IP2Bus_RdAck[1] ),
		.IP2Bus_WrAck	( mp_IP2Bus_WrAck[1] ),
		.IP2Bus_Error	( mp_IP2Bus_Error[1] ),

		.tbl_rd_req	( ipv4_fib_lut_rd_req ),
		.tbl_rd_ack	( ipv4_fib_lut_rd_ack ),
		.tbl_rd_addr	( ipv4_fib_lut_rd_addr ),
		.tbl_rd_data	( { 24'h000000, ipv4_fib_lut_rd_ipv4_oif,
					ipv4_fib_lut_rd_ipv4_nh,
					ipv4_fib_lut_rd_ipv4_mask,
					ipv4_fib_lut_rd_ipv4_net } ),
		.tbl_wr_req	( ipv4_fib_lut_wr_req ),
		.tbl_wr_ack	( ipv4_fib_lut_wr_ack ),
		.tbl_wr_addr	( ipv4_fib_lut_wr_addr ),
		.tbl_wr_data	( { ipv4_fib_lut_wr_ipv4_oif,
					ipv4_fib_lut_wr_ipv4_nh,
					ipv4_fib_lut_wr_ipv4_mask,
					ipv4_fib_lut_wr_ipv4_net } )
	);


	// ---------------------------------------------------------------------
	// ARP table
	// ---------------------------------------------------------------------

	// ---------------------------------------------------------------------
	// Local definitions:
	localparam	IPV4_ARP_LUT_COLS	= 3;
	localparam	IPV4_ARP_LUT_ROWS	= 32;
	localparam	IPV4_ARP_LUT_ROW_BITS	= log2(IPV4_ARP_LUT_ROWS);

	// Wires:
	wire					ipv4_arp_lut_rd_req;
	wire					ipv4_arp_lut_rd_ack;
	wire [IPV4_ARP_LUT_ROW_BITS-1:0]	ipv4_arp_lut_rd_addr;
	wire [MAC_WIDTH-1:0]			ipv4_arp_lut_rd_eth_addr;
	wire [31:0]				ipv4_arp_lut_rd_ipv4_addr;
	wire					ipv4_arp_lut_wr_req;
	wire					ipv4_arp_lut_wr_ack;
	wire [IPV4_ARP_LUT_ROW_BITS-1:0]	ipv4_arp_lut_wr_addr;
	//wire [MAC_WIDTH-1:0]			ipv4_arp_lut_wr_eth_addr;
	wire [64-1:0]				ipv4_arp_lut_wr_eth_addr;
	wire [31:0]				ipv4_arp_lut_wr_ipv4_addr;

	// ---------------------------------------------------------------------
	// ARP lookup table.
	ipif_table_regs
	#(
		.C_S_AXI_DATA_WIDTH	(C_S_AXI_DATA_WIDTH),
		.C_S_AXI_ADDR_WIDTH	(C_S_AXI_ADDR_WIDTH),
		.TBL_NUM_COLS		(IPV4_ARP_LUT_COLS),
		.TBL_NUM_ROWS		(IPV4_ARP_LUT_ROWS)
	) ipv4_arp_lut_ipif_table_regs_inst
	// inputs and outputs
	(
		.Bus2IP_Clk	( Bus2IP_Clk ),
		.Bus2IP_Resetn	( Bus2IP_Resetn ),
		.Bus2IP_Addr	( Bus2IP_Addr ),
				// BAR1 & ARP table
		.Bus2IP_CS	( Bus2IP_CS[0] & (Bus2IP_Addr[15:8] == 8'h40)),
		.Bus2IP_RNW	( Bus2IP_RNW ),
		.Bus2IP_Data	( Bus2IP_Data ),
		.Bus2IP_BE	( Bus2IP_BE ),
		.IP2Bus_Data	( mp_IP2Bus_Data[2] ),
		.IP2Bus_RdAck	( mp_IP2Bus_RdAck[2] ),
		.IP2Bus_WrAck	( mp_IP2Bus_WrAck[2] ),
		.IP2Bus_Error	( mp_IP2Bus_Error[2] ),

		.tbl_rd_req	( ipv4_arp_lut_rd_req ),
		.tbl_rd_ack	( ipv4_arp_lut_rd_ack ),
		.tbl_rd_addr	( ipv4_arp_lut_rd_addr ),
		.tbl_rd_data	( { 16'h0000, ipv4_arp_lut_rd_eth_addr,
					 ipv4_arp_lut_rd_ipv4_addr } ),
		.tbl_wr_req	( ipv4_arp_lut_wr_req ),
		.tbl_wr_ack	( ipv4_arp_lut_wr_ack ),
		.tbl_wr_addr	( ipv4_arp_lut_wr_addr ),
		.tbl_wr_data	( { ipv4_arp_lut_wr_eth_addr,
					ipv4_arp_lut_wr_ipv4_addr } )
	);


	// ---------------------------------------------------------------------

	// ---------------------------------------------------------------------
	// Instantiations of our modules.
	// ---------------------------------------------------------------------

	// Wires
	wire						w_eth_out_valid;
	wire						w_pkt_word1;
	wire						w_pkt_word2;
	wire						w_pkt_is_from_cpu;
	wire						w_pktstate_valid;
	wire						w_eth_is_for_us;
	wire						w_eth_is_bmcast;
`ifdef ASSIGNMENT_STAGE9
	wire						w_eth_is_arp;
`endif
	wire						w_eth_is_ipv4;
	wire						w_ipv4_can_handle_ipv4;
	wire						w_ipv4_ttl_ok;
	wire						w_ipv4_out_valid;
	wire						w_ipv4_csum_ok;
	wire [15:0]					w_ipv4_csum_updated;
	wire						w_ipv4_csum_out_valid;
	//wire [31:0]					w_ipv4_daddr;
	wire						w_ipv4_local_lut_ipv4_daddr_is_local;
	wire						w_ipv4_local_lut_ipv4_daddr_is_local_valid;
	wire						w_ipv4_arp_lut_ipv4_eth_addr_found;
	wire [47:0]					w_ipv4_arp_lut_ipv4_eth_addr;
	wire						w_ipv4_arp_lut_valid;
	wire						w_ipv4_fib_lut_nh_found;
	//wire [31:0]					w_ipv4_fib_lut_nh;
	wire [7:0]					w_ipv4_fib_lut_tuser;
	wire						w_ipv4_fib_lut_valid;
	wire [31:0]					w_im_ipv4_fib_lut_nh;
	wire						w_im_ipv4_fib_lut_valid;
	wire						w_in_fifo_nearly_full;
	wire						w_rd_from_magic;
	wire [31:0]					w_im_ipv4_daddr;
	wire						w_im_ipv4_daddr_valid;

	// Stats counter wiring.
	wire						w_counter_pkts_eth_bad_dst;
	wire						w_counter_pkts_not_ip4;
	wire						w_counter_pkts_to_cpu;
	wire						w_counter_pkts_ip4_options;
	wire						w_counter_pkts_ip4_bad_csum;
	wire						w_counter_pkts_ip4_bad_ttl;
	wire						w_counter_pkts_ip4_fwd;
	wire						w_counter_pkts_ip4_local;
	wire						w_counter_lpm_misses;
	wire						w_counter_arp_misses;

	// Spaghetti
	//assign	...				= ...;

	// ---------------------------------------------------------------------
	// Magic!
	magic
	#(
		.C_S_AXIS_DATA_WIDTH	(C_S_AXIS_DATA_WIDTH),
		.C_S_AXIS_TUSER_WIDTH	(C_S_AXIS_TUSER_WIDTH),
		.C_M_AXIS_DATA_WIDTH	(C_M_AXIS_DATA_WIDTH),
		.C_M_AXIS_TUSER_WIDTH	(C_M_AXIS_TUSER_WIDTH),
		.SRC_PORT_POS		(SRC_PORT_POS),
		.DST_PORT_POS		(DST_PORT_POS),
		.MAC_WIDTH		(MAC_WIDTH)
	) magic_inst
	// inputs and outputs
	(
		.clk				(AXI_ACLK),
		.reset				(~AXI_RESETN),
		// Up-/Downstream connects.
		.S_AXIS_TDATA			(S_AXIS_TDATA),
		.S_AXIS_TSTRB			(S_AXIS_TSTRB),
		.S_AXIS_TUSER			(S_AXIS_TUSER),
		.S_AXIS_TVALID			(S_AXIS_TVALID),
		.S_AXIS_TLAST			(S_AXIS_TLAST),
		.S_AXIS_TREADY			(S_AXIS_TREADY),
		.M_AXIS_TREADY			(M_AXIS_TREADY),
		.M_AXIS_TDATA			(M_AXIS_TDATA),
		.M_AXIS_TSTRB			(M_AXIS_TSTRB),
		.M_AXIS_TUSER			(M_AXIS_TUSER),
		.M_AXIS_TVALID			(M_AXIS_TVALID),
		.M_AXIS_TLAST			(M_AXIS_TLAST),
		// Misc
		.i_mac0				(mac_0),
		.i_mac1				(mac_1),
		.i_mac2				(mac_2),
		.i_mac3				(mac_3),
		// State1
		// - pktstate
		.i_pkt_is_from_cpu		(w_pkt_is_from_cpu),
		.i_pktstate_valid		(w_pktstate_valid),
		// - eth
		.i_eth_is_for_us		(w_eth_is_for_us),
		.i_eth_is_bmcast		(w_eth_is_bmcast),
		.i_eth_is_ipv4			(w_eth_is_ipv4),
		.i_eth_out_valid		(w_eth_out_valid),
		// - ipv4
		.i_ipv4_can_handle_ipv4		(w_ipv4_can_handle_ipv4),
		.i_ipv4_ttl_ok			(w_ipv4_ttl_ok),
		//.i_ipv4_daddr			(w_ipv4_daddr),
		.i_ipv4_out_valid		(w_ipv4_out_valid),
		.i_ipv4_csum_ok			(w_ipv4_csum_ok),		// Really in Stage2 but signal from stage 1 module
		.i_ipv4_csum_updated		(w_ipv4_csum_updated),		// Really in Stage2 but signal from stage 1 module
		.i_ipv4_csum_out_valid		(w_ipv4_csum_out_valid),	// Really in Stage2 but signal from stage 1 module
		// State2
		// - ipv4_local_lut
		.i_ipv4_daddr_is_local		(w_ipv4_local_lut_ipv4_daddr_is_local),
		.i_ipv4_daddr_is_local_valid	(w_ipv4_local_lut_ipv4_daddr_is_local_valid),
		// - ipv4_fib_lut
		.i_ipv4_fib_lut_nh_found	(w_ipv4_fib_lut_nh_found),
		//.i_ipv4_fib_lut_nh		(w_ipv4_fib_lut_nh),
		.i_ipv4_fib_lut_tuser		(w_ipv4_fib_lut_tuser),
		.i_ipv4_fib_lut_valid		(w_ipv4_fib_lut_valid),
		// State3
		// - ipv4_arp_lut
		.i_ipv4_arp_lut_ipv4_eth_addr_found (w_ipv4_arp_lut_ipv4_eth_addr_found),
		.i_ipv4_arp_lut_ipv4_eth_addr	(w_ipv4_arp_lut_ipv4_eth_addr),
		.i_ipv4_arp_lut_valid		(w_ipv4_arp_lut_valid),
		// outputs
		.o_rd_from_magic		(w_rd_from_magic),
		.o_in_fifo_nearly_full		(w_in_fifo_nearly_full),
		// Stats counters.
		.o_counter_pkts_eth_bad_dst	(w_counter_pkts_eth_bad_dst),
		.o_counter_pkts_not_ip4		(w_counter_pkts_not_ip4),
		.o_counter_pkts_to_cpu		(w_counter_pkts_to_cpu),
		.o_counter_pkts_ip4_options	(w_counter_pkts_ip4_options),
		.o_counter_pkts_ip4_bad_csum	(w_counter_pkts_ip4_bad_csum),
		.o_counter_pkts_ip4_bad_ttl	(w_counter_pkts_ip4_bad_ttl),
		.o_counter_pkts_ip4_fwd		(w_counter_pkts_ip4_fwd),
		.o_counter_pkts_ip4_local	(w_counter_pkts_ip4_local),
		.o_counter_lpm_misses		(w_counter_lpm_misses),
		.o_counter_arp_misses		(w_counter_arp_misses)
`ifdef ASSIGNMENT_STAGE9
		,
		.o_counter_pkts_arp		(w_counter_pkts_arp),
		.o_counter_pkts_ip4		(w_counter_pkts_ip4),
		.o_counter_pkts_ospf		(w_counter_pkts_ospf)
`endif
	);

	// ---------------------------------------------------------------------
	// Packet state
	pktstate
	#(
		.C_S_AXIS_TUSER_WIDTH	(C_S_AXIS_TUSER_WIDTH)
	) pktstate_inst
	// inputs and outputs
	(
		.clk				(AXI_ACLK),
		.reset				(~AXI_RESETN),
		.i_tuser			(S_AXIS_TUSER),
						// Keep in sync with input FIFO in magic.
		.i_tvalid			(S_AXIS_TVALID & ~w_in_fifo_nearly_full),
		.i_tlast			(S_AXIS_TLAST),
		.i_rd_from_magic		(w_rd_from_magic),
		.o_pkt_word1			(w_pkt_word1),
		.o_pkt_word2			(w_pkt_word2),
		.o_pkt_is_from_cpu		(w_pkt_is_from_cpu),
		.o_pktstate_valid		(w_pktstate_valid)
	);
  
	// ---------------------------------------------------------------------
	// Ethernet layer
	eth
	#(
		.C_S_AXIS_TDATA_WIDTH	(C_S_AXIS_DATA_WIDTH),
		.C_S_AXIS_TUSER_WIDTH	(C_S_AXIS_TUSER_WIDTH),
		.MAC_WIDTH		(MAC_WIDTH)
	) eth_inst
	// inputs and outputs
	(
		.clk				(AXI_ACLK),
		.reset				(~AXI_RESETN),
		.i_tdata			(S_AXIS_TDATA),
		.i_tuser			(S_AXIS_TUSER),
		.i_pkt_word1			(w_pkt_word1),
		.i_mac0				(mac_0),
		.i_mac1				(mac_1),
		.i_mac2				(mac_2),
		.i_mac3				(mac_3),
		.i_rd_from_magic		(w_rd_from_magic),
		.o_is_for_us			(w_eth_is_for_us),
		.o_is_bmcast			(w_eth_is_bmcast),
`ifdef ASSIGNMENT_STAGE9
		.o_is_arp			(w_eth_is_arp),		// XXX-BZ antenna; unless we update the counter anyway
`endif
		.o_is_ipv4			(w_eth_is_ipv4),
		.o_eth_out_valid		(w_eth_out_valid)
	);

	// ---------------------------------------------------------------------
	// IPv4 layer
	ipv4
	#(
		.C_S_AXIS_TDATA_WIDTH	(C_S_AXIS_DATA_WIDTH)
	) ipv4_inst
	// inputs and outputs
	(
		.clk				(AXI_ACLK),
		.reset				(~AXI_RESETN),
		.i_tdata			(S_AXIS_TDATA),
		.i_pkt_word1			(w_pkt_word1),
		.i_pkt_word2			(w_pkt_word2),
		.i_rd_from_magic		(w_rd_from_magic),
		// IPv4 options, ttl, daddr.
		.o_can_handle_ipv4		(w_ipv4_can_handle_ipv4),
		.o_ipv4_ttl_ok			(w_ipv4_ttl_ok),
		//.o_ipv4_daddr			(w_ipv4_daddr),
		.o_ipv4_out_valid		(w_ipv4_out_valid),
		// Immediate outputs for LUTs.
		.o_im_ipv4_daddr		(w_im_ipv4_daddr),
		.o_im_ipv4_daddr_valid		(w_im_ipv4_daddr_valid),
		// Csum 3cy
		.o_ipv4_csum_ok			(w_ipv4_csum_ok),
		.o_ipv4_csum_updated		(w_ipv4_csum_updated),
		.o_ipv4_csum_out_valid		(w_ipv4_csum_out_valid)
	);

	// ---------------------------------------------------------------------
	// Local IPv4 lookup
	ipv4_local_lut
	#(
		.IPV4_LOCAL_LUT_ROWS	(IPV4_LOCAL_LUT_ROWS),
		.IPV4_LOCAL_LUT_ROW_BITS (IPV4_LOCAL_LUT_ROW_BITS)
	) ipv4_local_lut_inst
	// inputs and outputs
	(
		.Bus2IP_Clk			(Bus2IP_Clk),
		.Bus2IP_Reset			(~Bus2IP_Resetn),
		.i_ipv4_local_lut_rd_req	(ipv4_local_lut_rd_req),
		.o_ipv4_local_lut_rd_ack	(ipv4_local_lut_rd_ack),
		.i_ipv4_local_lut_rd_addr	(ipv4_local_lut_rd_addr),
		.o_ipv4_local_lut_rd_ipv4_addr	(ipv4_local_lut_rd_ipv4_addr),
		.i_ipv4_local_lut_wr_req	(ipv4_local_lut_wr_req),
		.o_ipv4_local_lut_wr_ack	(ipv4_local_lut_wr_ack),
		.i_ipv4_local_lut_wr_addr	(ipv4_local_lut_wr_addr),
		.i_ipv4_local_lut_wr_ipv4_addr	(ipv4_local_lut_wr_ipv4_addr),

		.clk				(AXI_ACLK),
		.reset				(~AXI_RESETN),
		.i_rd_from_magic		(w_rd_from_magic),
		.i_ipv4_local_lut_ipv4_daddr	(w_im_ipv4_daddr),
		.i_ipv4_local_lut_ipv4_daddr_valid (w_im_ipv4_daddr_valid),
		.o_ipv4_local_lut_ipv4_daddr_is_local (w_ipv4_local_lut_ipv4_daddr_is_local),
		.o_ipv4_local_lut_ipv4_daddr_is_local_valid (w_ipv4_local_lut_ipv4_daddr_is_local_valid)
	);

	// ---------------------------------------------------------------------
	// IPv4 longest prefix match
	ipv4_fib_lut
	#(
		.IPV4_FIB_LUT_ROWS	(IPV4_FIB_LUT_ROWS),
		.IPV4_FIB_LUT_ROW_BITS	(IPV4_FIB_LUT_ROW_BITS)
	) ipv4_fib_lut_inst
	// inputs and outputs
	(
		.Bus2IP_Clk			(Bus2IP_Clk),
		.Bus2IP_Reset			(~Bus2IP_Resetn),
		.i_ipv4_fib_lut_rd_req		(ipv4_fib_lut_rd_req),
		.o_ipv4_fib_lut_rd_ack		(ipv4_fib_lut_rd_ack),
		.i_ipv4_fib_lut_rd_addr		(ipv4_fib_lut_rd_addr),
		.o_ipv4_fib_lut_rd_ipv4_oif	(ipv4_fib_lut_rd_ipv4_oif),
		.o_ipv4_fib_lut_rd_ipv4_nh	(ipv4_fib_lut_rd_ipv4_nh),
		.o_ipv4_fib_lut_rd_ipv4_mask	(ipv4_fib_lut_rd_ipv4_mask),
		.o_ipv4_fib_lut_rd_ipv4_net	(ipv4_fib_lut_rd_ipv4_net),
		.i_ipv4_fib_lut_wr_req		(ipv4_fib_lut_wr_req),
		.o_ipv4_fib_lut_wr_ack		(ipv4_fib_lut_wr_ack),
		.i_ipv4_fib_lut_wr_addr		(ipv4_fib_lut_wr_addr),
		.i_ipv4_fib_lut_wr_ipv4_oif	(ipv4_fib_lut_wr_ipv4_oif),
		.i_ipv4_fib_lut_wr_ipv4_nh	(ipv4_fib_lut_wr_ipv4_nh),
		.i_ipv4_fib_lut_wr_ipv4_mask	(ipv4_fib_lut_wr_ipv4_mask),
		.i_ipv4_fib_lut_wr_ipv4_net	(ipv4_fib_lut_wr_ipv4_net),

		.clk				(AXI_ACLK),
		.reset				(~AXI_RESETN),
		.i_rd_from_magic		(w_rd_from_magic),
		.i_ipv4_fib_lut_daddr		(w_im_ipv4_daddr),
		.i_ipv4_fib_lut_daddr_valid	(w_im_ipv4_daddr_valid),
		.o_ipv4_fib_lut_nh_found	(w_ipv4_fib_lut_nh_found),
		//.o_ipv4_fib_lut_nh		(w_ipv4_fib_lut_nh),
		.o_ipv4_fib_lut_tuser		(w_ipv4_fib_lut_tuser),
		.o_ipv4_fib_lut_valid		(w_ipv4_fib_lut_valid),
		.o_im_ipv4_fib_lut_nh		(w_im_ipv4_fib_lut_nh),
		.o_im_ipv4_fib_lut_valid	(w_im_ipv4_fib_lut_valid)
	);

	// ---------------------------------------------------------------------
	// IPv4 ARP lookup
	ipv4_arp_lut
	#(
		.IPV4_ARP_LUT_ROWS	(IPV4_ARP_LUT_ROWS),
		.IPV4_ARP_LUT_ROW_BITS	(IPV4_ARP_LUT_ROW_BITS),
		.MAC_WIDTH		(MAC_WIDTH)
	) ipv4_arp_lut_inst
	// inputs and outputs
	(
		.Bus2IP_Clk			(Bus2IP_Clk),
		.Bus2IP_Reset			(~Bus2IP_Resetn),
		.i_ipv4_arp_lut_rd_req		(ipv4_arp_lut_rd_req),
		.o_ipv4_arp_lut_rd_ack		(ipv4_arp_lut_rd_ack),
		.i_ipv4_arp_lut_rd_addr		(ipv4_arp_lut_rd_addr),
		.o_ipv4_arp_lut_rd_eth_addr	(ipv4_arp_lut_rd_eth_addr),
		.o_ipv4_arp_lut_rd_ipv4_addr	(ipv4_arp_lut_rd_ipv4_addr),
		.i_ipv4_arp_lut_wr_req		(ipv4_arp_lut_wr_req),
		.o_ipv4_arp_lut_wr_ack		(ipv4_arp_lut_wr_ack),
		.i_ipv4_arp_lut_wr_addr		(ipv4_arp_lut_wr_addr),
		.i_ipv4_arp_lut_wr_eth_addr	(ipv4_arp_lut_wr_eth_addr),
		.i_ipv4_arp_lut_wr_ipv4_addr	(ipv4_arp_lut_wr_ipv4_addr),

		.clk				(AXI_ACLK),
		.reset				(~AXI_RESETN),
		.i_rd_from_magic		(w_rd_from_magic),
		.i_ipv4_arp_lut_ipv4_daddr_valid (w_im_ipv4_daddr_valid),	// From IPv4
		.i_ipv4_arp_lut_ipv4_daddr	(w_im_ipv4_daddr),
		.i_ipv4_arp_lut_fib_daddr_valid (w_im_ipv4_fib_lut_valid),	// From FIB
		.i_ipv4_arp_lut_fib_daddr	(w_im_ipv4_fib_lut_nh),
		.o_ipv4_arp_lut_ipv4_eth_addr_found (w_ipv4_arp_lut_ipv4_eth_addr_found),
		.o_ipv4_arp_lut_ipv4_eth_addr	(w_ipv4_arp_lut_ipv4_eth_addr),
		.o_ipv4_arp_lut_valid		(w_ipv4_arp_lut_valid)
	);


  // ---------------------------------------------------------------------------
  // Clockwork:
  // Update statistic counters.
  always @ (posedge AXI_ACLK) begin
	if (~AXI_RESETN || counter_zero_all) begin
		// Upon reset signal or
		// a register write singalling zero all counters.
		// What a horrible syntax, n-sized array of single-bit 0s.
		// Still wonder if "<= 0" would just do the right thing?
		r_counter_pkts_eth_bad_dst		<= {C_S_AXI_DATA_WIDTH{1'b0}};
		r_counter_pkts_not_ip4			<= {C_S_AXI_DATA_WIDTH{1'b0}};
		r_counter_pkts_to_cpu			<= {C_S_AXI_DATA_WIDTH{1'b0}};
		r_counter_pkts_ip4_options		<= {C_S_AXI_DATA_WIDTH{1'b0}};
		r_counter_pkts_ip4_bad_csum		<= {C_S_AXI_DATA_WIDTH{1'b0}};
		r_counter_pkts_ip4_bad_ttl		<= {C_S_AXI_DATA_WIDTH{1'b0}};
		r_counter_pkts_ip4_fwd			<= {C_S_AXI_DATA_WIDTH{1'b0}};
		r_counter_pkts_ip4_local		<= {C_S_AXI_DATA_WIDTH{1'b0}};
		r_counter_lpm_misses			<= {C_S_AXI_DATA_WIDTH{1'b0}};
		r_counter_arp_misses			<= {C_S_AXI_DATA_WIDTH{1'b0}};
		// +3 for earlier assignments
		r_counter_pkts_arp			<= {C_S_AXI_DATA_WIDTH{1'b0}};
		r_counter_pkts_ip4			<= {C_S_AXI_DATA_WIDTH{1'b0}};
		r_counter_pkts_ospf			<= {C_S_AXI_DATA_WIDTH{1'b0}};
        end else begin
		if (w_counter_pkts_eth_bad_dst)
			r_counter_pkts_eth_bad_dst	<= r_counter_pkts_eth_bad_dst + 1;
		if (w_counter_pkts_not_ip4)
			r_counter_pkts_not_ip4		<= r_counter_pkts_not_ip4 + 1;
		if (w_counter_pkts_to_cpu)
			r_counter_pkts_to_cpu		<= r_counter_pkts_to_cpu + 1;
		if (w_counter_pkts_ip4_options)
			r_counter_pkts_ip4_options	<= r_counter_pkts_ip4_options + 1;
		if (w_counter_pkts_ip4_bad_csum)
			r_counter_pkts_ip4_bad_csum	<= r_counter_pkts_ip4_bad_csum + 1;
		if (w_counter_pkts_ip4_bad_ttl)
			r_counter_pkts_ip4_bad_ttl	<= r_counter_pkts_ip4_bad_ttl + 1;
		if (w_counter_pkts_ip4_fwd)
			r_counter_pkts_ip4_fwd		<= r_counter_pkts_ip4_fwd + 1;
		if (w_counter_pkts_ip4_local)
			r_counter_pkts_ip4_local	<= r_counter_pkts_ip4_local + 1;
		if (w_counter_lpm_misses)
			r_counter_lpm_misses		<= r_counter_lpm_misses + 1;
		if (w_counter_arp_misses)
			r_counter_arp_misses		<= r_counter_arp_misses + 1;
		// DEBUGGING:
		r_counter_pkts_ospf[0] <= w_pktstate_valid;					// 0x01
		r_counter_pkts_ospf[1] <= w_eth_out_valid;					// 0x02
		r_counter_pkts_ospf[2] <= w_ipv4_out_valid;					// 0x04
		r_counter_pkts_ospf[3] <= w_ipv4_csum_out_valid;				// 0x08
		r_counter_pkts_ospf[4] <= w_ipv4_local_lut_ipv4_daddr_is_local_valid;		// 0x10
		r_counter_pkts_ospf[5] <= w_ipv4_fib_lut_valid;					// 0x20
		r_counter_pkts_ospf[6] <= w_ipv4_arp_lut_valid;					// 0x40
`ifdef ASSIGNMENT_STAGE9
		if (w_counter_pkts_arp)
			r_counter_pkts_arp		<= r_counter_pkts_arp + 1;
		if (w_counter_pkts_ip4)
			r_counter_pkts_ip4		<= r_counter_pkts_ip4 + 1;
		if (w_counter_pkts_ospf)
			r_counter_pkts_ospf		<= r_counter_pkts_ospf + 1;
`endif
        end
  end

endmodule // output_port_lookup
