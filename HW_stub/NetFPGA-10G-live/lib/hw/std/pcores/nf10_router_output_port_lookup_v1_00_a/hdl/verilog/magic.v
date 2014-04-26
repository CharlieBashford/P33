/*-
 * Copyright (c) 2014, Bjoern A. Zeeb
 * All rights reserved.
 *
 * Magic happens here.
 *
 * Depending on state this takes all our output signals from various modules
 * and makes the decision on whether to forward the packet directly (to mac or
 * cpu), to discard the packet, or to further process it.
 */
module magic
	// ---------------------------------------------------------------------
	#(
		parameter C_S_AXIS_DATA_WIDTH=256,
		parameter C_S_AXIS_TUSER_WIDTH=128,
		parameter C_M_AXIS_DATA_WIDTH=256,
		parameter C_M_AXIS_TUSER_WIDTH=128,
		parameter SRC_PORT_POS=16,
		parameter DST_PORT_POS=24,
		parameter MAC_WIDTH=48
	)
	// inputs and outputs
	(
		// Always need these; no special prefix.
		input					clk,
		input					reset,

		// Up-/Dowstream (input arbiter/output bram) connections.
		// Slave Stream Ports (interface from RX queues)
		input [C_S_AXIS_DATA_WIDTH-1:0] 	S_AXIS_TDATA,
		input [(C_S_AXIS_DATA_WIDTH/8)-1:0]	S_AXIS_TSTRB,
		input [C_S_AXIS_TUSER_WIDTH-1:0] 	S_AXIS_TUSER,
		input					S_AXIS_TVALID,
		input					S_AXIS_TLAST,
		output					S_AXIS_TREADY,

		// Master Stream Ports (interface to TX data path)
		input					M_AXIS_TREADY,
		output reg [C_M_AXIS_DATA_WIDTH-1:0] 	M_AXIS_TDATA,
		output reg [(C_M_AXIS_DATA_WIDTH/8)-1:0] M_AXIS_TSTRB,
		output reg [C_M_AXIS_TUSER_WIDTH-1:0]	M_AXIS_TUSER,
		output reg 				M_AXIS_TVALID,
		output reg 				M_AXIS_TLAST,

		// Misc
		input [MAC_WIDTH-1:0]			i_mac0,
		input [MAC_WIDTH-1:0]			i_mac1,
		input [MAC_WIDTH-1:0]			i_mac2,
		input [MAC_WIDTH-1:0]			i_mac3,

		// State1
		// - pktstate
		input					i_pkt_is_from_cpu,	// if, pass untouched
		input					i_pktstate_valid,	// (V,1)
		// - eth
		input					i_eth_is_for_us,	// if not, DISCARD
		input					i_eth_is_bmcast,	// if, go to CPU
		input					i_eth_is_ipv4,
		input					i_eth_out_valid,	// (V,2)
		// - ipv4
		input					i_ipv4_can_handle_ipv4,	// if not, go to CPU, e.g., has options
		input					i_ipv4_ttl_ok,		// if not, go to CPU
		input [31:0]				i_ipv4_daddr,
		input					i_ipv4_out_valid,	// (V,3)
		// - ipv4 + 1cy
		input					i_ipv4_csum_ok,		// if not, DISCARD
		input [15:0]				i_ipv4_csum_updated,
		input					i_ipv4_csum_out_valid,	// (V,4)
		// State2
		// - ipv4_local_lut
		input					i_ipv4_daddr_is_local,	// ifm go to CPU
		input					i_ipv4_daddr_is_local_valid, // (V,5)
		// - ipv4_fib_lut
		input					i_ipv4_fib_lut_nh_found,// if not, go to CPU
		input [31:0]				i_ipv4_fib_lut_nh,
		input [7:0]				i_ipv4_fib_lut_tuser,
		input					i_ipv4_fib_lut_valid,	// (V,6)
		// State3
		// - ipv4_arp_lut
		input					i_ipv4_arp_lut_ipv4_eth_addr_found, // if not, go to CPU
		input [MAC_WIDTH-1:0]			i_ipv4_arp_lut_ipv4_eth_addr,
		input					i_ipv4_arp_lut_valid,	// (V,7)

		// outputs
		output reg				o_rd_from_magic,
		output					o_in_fifo_nearly_full,

		output reg				o_counter_pkts_eth_bad_dst,
		output reg				o_counter_pkts_not_ip4,
		output reg				o_counter_pkts_to_cpu,
		output reg				o_counter_pkts_ip4_options,
		output reg				o_counter_pkts_ip4_bad_csum,
		output reg				o_counter_pkts_ip4_bad_ttl,
		output reg				o_counter_pkts_ip4_fwd,
		output reg				o_counter_pkts_ip4_local,
		output reg				o_counter_lpm_misses,
		output reg				o_counter_arp_misses,
		// ASSIGNMENT_STAGE9
		output reg				o_counter_pkts_arp,
		output reg				o_counter_pkts_ip4,
		output reg				o_counter_pkts_ospf
	);


	// ---------------------------------------------------------------------
	// Pktstate, ethernet, ipv4 stage.
	// ---------------------------------------------------------------------

	// Parameters.
	localparam				ONE_STATE_START		= 1;
	localparam				ONE_STATE_PIPE		= 2;

	// Register.
	reg					r_stage1_fifo_rd_en;
	reg [1:0]				r_1_state, r_1_state_next;

	// Birds on the wire.
	wire					w_stage2_fifo_nearly_full;
	wire					w_stage1_fifo_nearly_full;
	wire					w_stage1_fifo_empty;
	wire [C_M_AXIS_DATA_WIDTH-1:0] 		w_1_tdata;
	wire [(C_M_AXIS_DATA_WIDTH/8)-1:0]	w_1_tstrb;
	wire [C_M_AXIS_TUSER_WIDTH-1:0]		w_1_tuser;
	wire					w_1_tlast;

	// Spaghetti.
	assign S_AXIS_TREADY			= !w_stage1_fifo_nearly_full;
	assign o_in_fifo_nearly_full		= w_stage1_fifo_nearly_full;

	// ---------------------------------------------------------------------
	// FIFO.
	fallthrough_small_fifo
	#(
		.WIDTH(1 + C_M_AXIS_TUSER_WIDTH + (C_M_AXIS_DATA_WIDTH/8)+1 + C_M_AXIS_DATA_WIDTH),
		.MAX_DEPTH_BITS(2)
	) stage1
	// inputs and outputs
	(
		// Inputs
		.clk		(clk),
		.reset		(reset),
		.din		({S_AXIS_TLAST, S_AXIS_TUSER, S_AXIS_TSTRB, S_AXIS_TDATA}),
		.rd_en		(/* r_stage1_fifo_rd_en */ !w_stage1_fifo_empty & !w_stage2_fifo_nearly_full),
		.wr_en		(S_AXIS_TVALID & !w_stage1_fifo_nearly_full),
		// Outputs
		.dout		({w_1_tlast, w_1_tuser, w_1_tstrb, w_1_tdata}),
		.full		(),
		.nearly_full	(w_stage1_fifo_nearly_full),
		.prog_full	(),
		.empty		(w_stage1_fifo_empty)
	);

/*
	always @(*) begin
		r_stage1_fifo_rd_en	= 0;
		r_1_state_next		= r_1_state;

		case (r_1_state)
		ONE_STATE_START: begin
			if (!w_stage1_fifo_empty & !w_stage2_fifo_nearly_full) begin
				r_stage1_fifo_rd_en = 1;
				r_1_state_next = ONE_STATE_PIPE;
			end
		end

		ONE_STATE_PIPE: begin
			if (!w_stage1_fifo_empty & !w_stage2_fifo_nearly_full) begin
				r_stage1_fifo_rd_en = 1;
				if (w_1_tlast)
					r_1_state_next = ONE_STATE_START;
			end
		end
		endcase
	end

	always @(posedge clk) begin
		if (reset) begin
			r_1_state		<= ONE_STATE_START;
		end else begin
			r_1_state		<= r_1_state_next;
		end
	end
*/

	// ---------------------------------------------------------------------
	// IPv4 Local/FIB lookup stage.
	// ---------------------------------------------------------------------

	// Parameters.
	localparam				TWO_STATE_START		= 1;
	localparam				TWO_STATE_PIPE		= 2;

	// Register.
	reg					r_stage2_fifo_rd_en;
	reg [1:0]				r_2_state, r_2_state_next;

	// Birds on the wire.
	wire					w_stage3_fifo_nearly_full;
	wire					w_stage2_fifo_empty;
	wire [C_M_AXIS_DATA_WIDTH-1:0] 		w_2_tdata;
	wire [(C_M_AXIS_DATA_WIDTH/8)-1:0]	w_2_tstrb;
	wire [C_M_AXIS_TUSER_WIDTH-1:0]		w_2_tuser;
	wire					w_2_tlast;
	// State1 output signals, add to the data.
/*
	wire					w_1_is_from_cpu;
	wire					w_1_is_valid;
	wire					w_1_to_cpu;
	wire					w_2_is_from_cpu;
	wire					w_2_is_valid;
	wire					w_2_to_cpu;

	// Spaghetti.
	assign w_1_is_from_cpu			= (i_pkt_word2) ? i_pkt_is_from_cpu : 0;
	assign w_1_is_valid			= (i_pkt_word2) ? i_eth_valid : 0;				// XXX-BZ BOGUS NOW
	assign w_1_to_cpu			= (i_pkt_word2) ? (i_eth_is_bmcast | i_ipv4_to_cpu) : 0;
*/

	// ---------------------------------------------------------------------
	// FIFO.
	fallthrough_small_fifo
	#(
		.WIDTH(1 + C_M_AXIS_TUSER_WIDTH + (C_M_AXIS_DATA_WIDTH/8)+1 + C_M_AXIS_DATA_WIDTH /*+ 3*/),
		.MAX_DEPTH_BITS(2)
	) stage2
	// inputs and outputs
	(
		// Inputs
		.clk		(clk),
		.reset		(reset),
		.din		({w_1_tlast, w_1_tuser, w_1_tstrb, w_1_tdata /*,
				    w_1_is_from_cpu, w_1_is_valid, w_1_to_cpu */}),
		.rd_en		(/*r_stage2_fifo_rd_en*/ !w_stage2_fifo_empty & !w_stage3_fifo_nearly_full),
		.wr_en		(!w_stage1_fifo_empty & !w_stage2_fifo_nearly_full),
		// Outputs
		.dout		({w_2_tlast, w_2_tuser, w_2_tstrb, w_2_tdata /*,
				    w_2_is_from_cpu, w_2_is_valid, w_2_to_cpu */}),
		.full		(),
		.nearly_full	(w_stage2_fifo_nearly_full),
		.prog_full	(),
		.empty		(w_stage2_fifo_empty)
	);

/*
	always @(*) begin
		r_stage2_fifo_rd_en	= 0;
		r_2_state_next		= r_2_state;

		case (r_2_state)
		TWO_STATE_START: begin
			if (!w_stage2_fifo_empty & !w_stage3_fifo_nearly_full) begin
				r_stage2_fifo_rd_en = 1;
				r_2_state_next = TWO_STATE_PIPE;
			end
		end

		TWO_STATE_PIPE: begin
			if (!w_stage2_fifo_empty & !w_stage3_fifo_nearly_full) begin
				r_stage2_fifo_rd_en = 1;
				if (w_2_tlast)
					r_2_state_next = TWO_STATE_START;
			end
		end
		endcase
	end

	always @(posedge clk) begin
		if (reset) begin
			r_2_state		<= TWO_STATE_START;
		end else begin
			r_2_state		<= r_2_state_next;
		end
	end
*/

	// ---------------------------------------------------------------------
	// IPv4 ARP Lookup/Output stage.
	// ---------------------------------------------------------------------
	// One clock cycle after IPv4 ARP lookup stage:
	// TVALID is already asserted and TUSER is set so that the BRAM output
	// queues can get their peak to see.  They will then only assert TREADY
	// once we get here and get the data.  We do NOT control TVALID here.

	// Definitions for the state machine (avoid 0 to ease debugging):
	localparam				OUT_STATE_TVALID	= 1;
	localparam				OUT_STATE_FIRST		= 2;
	localparam				OUT_STATE_PIPE		= 4;
	localparam				OUT_STATE_DROP		= 8;

	// Register.
	reg					r_stage3_fifo_rd_en;
	reg [3:0]				r_out_state, r_out_state_next;
	reg [C_M_AXIS_DATA_WIDTH-1:0] 		r_m_tdata_next;
	reg [(C_M_AXIS_DATA_WIDTH/8)-1:0]	r_m_tstrb_next;
	reg [C_M_AXIS_TUSER_WIDTH-1:0]		r_m_tuser_next;
	reg					r_m_tvalid_next;
	reg					r_m_tlast_next;

	reg [MAC_WIDTH-1:0]			r_seth_addr, r_seth_addr_next;
	reg [7:0]				r_ttl, r_ttl_next;

	// Birds on the wire.
	wire					w_stage3_fifo_empty;
	wire [C_M_AXIS_DATA_WIDTH-1:0] 		w_i_m_tdata;
	wire [(C_M_AXIS_DATA_WIDTH/8)-1:0]	w_i_m_tstrb;
	wire [C_M_AXIS_TUSER_WIDTH-1:0]		w_i_m_tuser;
	wire					w_i_m_tlast;
	wire					w_meta_ready;
	wire					w_discard;

	wire					w_3_to_cpu;
	wire					w_i_m_is_from_cpu;
	wire					w_i_m_discard;
	wire					w_i_m_to_cpu;
	wire					w_to_cpu;
	wire [15:0]				w_i_m_csum_updated;
	wire [7:0]				w_ipv4_tuser;

	// Spaghetti.
	assign	w_meta_ready			=
		i_pktstate_valid & i_eth_out_valid & i_ipv4_out_valid &
		i_ipv4_csum_out_valid & i_ipv4_daddr_is_local_valid &
		i_ipv4_fib_lut_valid & i_ipv4_arp_lut_valid;
	assign	w_discard			=
		(!i_eth_is_for_us & !i_eth_is_bmcast) |
		(i_eth_is_ipv4 & i_ipv4_can_handle_ipv4 & !i_ipv4_csum_ok);
	assign w_to_cpu				=
		i_eth_is_bmcast | !i_ipv4_can_handle_ipv4 | !i_ipv4_ttl_ok |
		i_ipv4_daddr_is_local | !i_ipv4_fib_lut_nh_found |
		!i_ipv4_arp_lut_ipv4_eth_addr_found;

	// ---------------------------------------------------------------------
	// FIFO.
	fallthrough_small_fifo
	#(
		.WIDTH(1 + C_M_AXIS_TUSER_WIDTH + (C_M_AXIS_DATA_WIDTH/8)+1 + C_M_AXIS_DATA_WIDTH /*+ 3 + 16 + 8*/),
		.MAX_DEPTH_BITS(2)
	) stage3
	// inputs and outputs
	(
		// Inputs
		.clk		(clk),
		.reset		(reset),
		.din		({w_2_tlast, w_2_tuser, w_2_tstrb, w_2_tdata /*,
				    w_2_is_from_cpu, w_3_discard, w_3_to_cpu,
				    i_ipv4_csum_updated, i_ipv4_tuser */}),
		.rd_en		(r_stage3_fifo_rd_en),
		.wr_en		(!w_stage2_fifo_empty & !w_stage3_fifo_nearly_full),
		// Outputs
		.dout		({w_i_m_tlast, w_i_m_tuser, w_i_m_tstrb, w_i_m_tdata /*,
				    w_i_m_is_from_cpu, w_i_m_discard, w_i_m_to_cpu,
				    w_i_m_csum_updated, w_ipv4_tuser*/}),
		.full		(),
		.nearly_full	(w_stage3_fifo_nearly_full),
		.prog_full	(),
		.empty		(w_stage3_fifo_empty)
	);

	always @(*) begin
		r_stage3_fifo_rd_en		= 0;
		r_out_state_next		= r_out_state;
		r_seth_addr_next		= r_seth_addr;
		r_ttl_next			= r_ttl;
		r_m_tdata_next			= w_i_m_tdata;
		r_m_tstrb_next			= w_i_m_tstrb;
		r_m_tuser_next			= w_i_m_tuser;
		r_m_tvalid_next			= 0;
		r_m_tlast_next			= w_i_m_tlast;
		o_rd_from_magic			= 0;
		o_counter_pkts_eth_bad_dst	= 0;
		o_counter_pkts_not_ip4		= 0;
		o_counter_pkts_to_cpu		= 0;
		o_counter_pkts_ip4_options	= 0;
		o_counter_pkts_ip4_bad_csum	= 0;
		o_counter_pkts_ip4_bad_ttl	= 0;
		o_counter_pkts_ip4_fwd		= 0;
		o_counter_pkts_ip4_local	= 0;
		o_counter_lpm_misses		= 0;
		o_counter_arp_misses		= 0;
`ifdef ASSIGNMENT_STAGE9
		o_counter_pkts_arp		= 0;
		o_counter_pkts_ip4		= 0;
		o_counter_pkts_osp		= 0;
`endif

		case (r_out_state)
		OUT_STATE_TVALID: begin
			// Assert TVALID at the end of this clk cycle.
			// In the next clk cycle the BRAM output queues
			// will then start reading the data at earliest
			// asserting M_AXIS_TREADY.

			if (!w_stage3_fifo_empty & w_meta_ready) begin

				if (!i_eth_is_for_us & ! i_eth_is_bmcast)
					o_counter_pkts_eth_bad_dst = 1;
				else if (!i_eth_is_ipv4)
					o_counter_pkts_not_ip4 = 1;
				else if (!i_ipv4_can_handle_ipv4)
					o_counter_pkts_ip4_options = 1;		// XXX This is Not IPv4 or Options
				else if (!i_ipv4_csum_ok)
					o_counter_pkts_ip4_bad_csum = 1;
				else if (!i_ipv4_fib_lut_nh_found)
					o_counter_lpm_misses = 1;
				else if (!i_ipv4_arp_lut_ipv4_eth_addr_found)
					o_counter_arp_misses = 1;

				if (i_pkt_is_from_cpu) begin
					// We do nothing but assert TVALID as
					// all fields are hopfully set correctly
					// already.
					r_m_tvalid_next = 1;
					r_out_state_next = OUT_STATE_FIRST;
					
				end else if (w_discard) begin
					// Start reading.  Read packet w/o
					// asserting TVALID.
					r_out_state_next = OUT_STATE_DROP;
					r_stage3_fifo_rd_en = 1;
					o_rd_from_magic = 1;

				end else begin
					// Either the packet goes to CPU,
					// or the packet gets forwarded.
					// Update TUSER.
					r_ttl_next = w_i_m_tdata[79:72] - 1; // XXX-BZ we should get that as input with the new csum?

					if (w_to_cpu || r_ttl_next < 1) begin
						// To CPU: set the dst DMA port
						// matching the input port.
						r_m_tuser_next[DST_PORT_POS+7:DST_PORT_POS] =
						     w_i_m_tuser[SRC_PORT_POS+7:SRC_PORT_POS] << 1;
						if (!i_ipv4_ttl_ok || r_ttl_next < 1)
							o_counter_pkts_ip4_bad_ttl = 1;
						else if (i_ipv4_daddr_is_local)
							o_counter_pkts_ip4_local = 1;
						else
							o_counter_pkts_to_cpu = 1;

					end else begin
						// Forward.
						// We should have a valid i_ipv4_tuser from the fifo.
						r_m_tuser_next[DST_PORT_POS+7:DST_PORT_POS] =
						    i_ipv4_fib_lut_tuser;

						o_counter_pkts_ip4_fwd = 1;

						case (i_ipv4_fib_lut_tuser & 8'b01010101)
						8'b01000000: begin
							r_seth_addr_next = i_mac3;
						end
						8'b00010000: begin
							r_seth_addr_next = i_mac2;
						end
						8'b00000100: begin
							r_seth_addr_next = i_mac1;
						end
						8'b00000001: begin
							r_seth_addr_next = i_mac0;
						end
						endcase
					end

					r_m_tvalid_next = 1;
					r_out_state_next = OUT_STATE_FIRST;
				end
			end
		end

		OUT_STATE_FIRST: begin
			// Keep the modified TUSER for another cycle.
			r_m_tuser_next = M_AXIS_TUSER;

			if (M_AXIS_TREADY & !w_stage3_fifo_empty) begin
				if (!i_pkt_is_from_cpu & !w_to_cpu) begin
					r_m_tdata_next = {
						i_ipv4_arp_lut_ipv4_eth_addr,
						r_seth_addr,
						w_i_m_tdata[159:80],
						r_ttl,
						w_i_m_tdata[71:64],
						i_ipv4_csum_updated,
						w_i_m_tdata[47:0]
						};
				end
				r_m_tvalid_next = 1;
				r_stage3_fifo_rd_en = 1;
				o_rd_from_magic = 1;
				r_out_state_next = OUT_STATE_PIPE;
			end
		end

		OUT_STATE_PIPE: begin
			if (!w_stage3_fifo_empty & M_AXIS_TREADY) begin
				r_stage3_fifo_rd_en = 1;
				r_m_tvalid_next = 1;
				if (w_i_m_tlast)
					r_out_state_next = OUT_STATE_TVALID;
			end
		end

		OUT_STATE_DROP: begin
			if (!w_stage3_fifo_empty) begin
				r_stage3_fifo_rd_en = 1;
				if (w_i_m_tlast)
					r_out_state_next = OUT_STATE_TVALID;
			end
		end
		endcase
	end

	always @(posedge clk) begin
		if (reset) begin
			r_out_state		<= OUT_STATE_TVALID;
			r_seth_addr		<= 0;
			r_ttl			<= 0;
			M_AXIS_TDATA		<= 0;
			M_AXIS_TSTRB		<= 0;
			M_AXIS_TUSER		<= 0;
			M_AXIS_TVALID		<= 0;
			M_AXIS_TLAST		<= 0;
		end else begin
			r_out_state		<= r_out_state_next;
			r_seth_addr		<= r_seth_addr_next;
			r_ttl			<= r_ttl_next;
			M_AXIS_TDATA		<= r_m_tdata_next;
			M_AXIS_TSTRB		<= r_m_tstrb_next;
			M_AXIS_TUSER		<= r_m_tuser_next;
			M_AXIS_TVALID		<= r_m_tvalid_next;
			M_AXIS_TLAST		<= r_m_tlast_next;
		end
	end

endmodule // magic
