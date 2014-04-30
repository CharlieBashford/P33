/*-
 * Copyright (c) 2014, Bjoern A. Zeeb
 * All rights reserved.
 *
 * IPv4 FIB table.
 *
 * Lookup next hop (NH) and output queue for a given destination address.
 * Provide the interface to user space for updating the table.
 * 
 * Table layout:
 *	 8 bit output interface (well, 4, 5 bit, or 8bit? tuser or decimal?)
 *	32 bit next hop
 *	32 bit netmask
 *	32 bit network
 */
module ipv4_fib_lut
	// ---------------------------------------------------------------------
	#(
		parameter IPV4_FIB_LUT_ROWS=32,
		parameter IPV4_FIB_LUT_ROW_BITS=5
	)
	// inputs and outputs
	(
		// Always need these; no special prefix.
		input				Bus2IP_Clk,
		input				Bus2IP_Reset,

		// Table management from the register interface/axi.
		// (Keep ordering as in ipif_table_regs.)
		input					i_ipv4_fib_lut_rd_req,
		output reg				o_ipv4_fib_lut_rd_ack,
		input [IPV4_FIB_LUT_ROW_BITS-1:0]	i_ipv4_fib_lut_rd_addr,
		output [7:0]				o_ipv4_fib_lut_rd_ipv4_oif,
		output [31:0]				o_ipv4_fib_lut_rd_ipv4_nh,
		output [31:0]				o_ipv4_fib_lut_rd_ipv4_mask,
		output [31:0]				o_ipv4_fib_lut_rd_ipv4_net,
		input					i_ipv4_fib_lut_wr_req,
		output reg				o_ipv4_fib_lut_wr_ack,
		input [IPV4_FIB_LUT_ROW_BITS-1:0]	i_ipv4_fib_lut_wr_addr,
		// Keep input aligned with register interfcae width to avoid warning.
		input [7:0]				i_ipv4_fib_lut_wr_ipv4_oif,
		input [31:0]				i_ipv4_fib_lut_wr_ipv4_nh,
		input [31:0]				i_ipv4_fib_lut_wr_ipv4_mask,
		input [31:0]				i_ipv4_fib_lut_wr_ipv4_net,

		// Always need these; no special prefix.
		input					clk,
		input					reset,
	
		// Trigger reads from state FIFO(s).
		input					i_rd_from_magic,
		// In-HW access for lookups.
		// Destination address to lookup.
		input [31:0]				i_ipv4_fib_lut_daddr,
		input					i_ipv4_fib_lut_daddr_valid,
		// NH found (and with that valid) and NH address.
		output 					o_ipv4_fib_lut_nh_found,
`ifdef NOT_DISABLE_UNSUED
		output [31:0]				o_ipv4_fib_lut_nh,
`endif
		output [7:0]				o_ipv4_fib_lut_tuser,
		output					o_ipv4_fib_lut_valid,
		// Immediate outputs for ipv4_arp_lut.
		output reg [31:0]			o_im_ipv4_fib_lut_nh,
		output reg				o_im_ipv4_fib_lut_valid
	);

	// ---------------------------------------------------------------------
	// Defines
`define	FIB_LOOKUP_HSIMPLE 1

	// Definitions 
	//localparam	...			= ..;

	// Birds on wires..
	//wire	...				w_...;

	// Local register(s) to keep track of ...
	// 32 { IPv4 net/mask/nh entries (32 bit each), output queue (8 bit?) }
	// XXX-BZ In case of !FIB_LOOKUP_FOR_LOOPS we do not store the original
	// input network and mask in order to reduce resources, and will have
	// x bits in the network when reading as well.
	// XXX-BZ this makes reading the FIB from HW kindof useless.
	reg[7:0]		ipv4_fib_table_oif  [0:IPV4_FIB_LUT_ROWS-1];
	reg[31:0]		ipv4_fib_table_nh   [0:IPV4_FIB_LUT_ROWS-1];
`ifdef FIB_LOOKUP_FOR_LOOPS
	reg[31:0]		ipv4_fib_table_mask [0:IPV4_FIB_LUT_ROWS-1];
`else
	reg[31:0]		r_ipv4_fib_mask;
	reg[IPV4_FIB_LUT_ROW_BITS-1:0]	r_ipv4_fib_idx;
`endif
	reg[31:0]		ipv4_fib_table_net  [0:IPV4_FIB_LUT_ROWS-1];
	reg[IPV4_FIB_LUT_ROW_BITS-1:0]		row_num_select;

	integer					i;
	integer					z;

	// Spaghetti.
	assign o_ipv4_fib_lut_rd_ipv4_oif	=
		ipv4_fib_table_oif[row_num_select];
	assign o_ipv4_fib_lut_rd_ipv4_nh	=
		ipv4_fib_table_nh[row_num_select];
`ifdef FIB_LOOKUP_FOR_LOOPS
	assign o_ipv4_fib_lut_rd_ipv4_mask	=
		ipv4_fib_table_mask[row_num_select];
`else
	assign o_ipv4_fib_lut_rd_ipv4_mask	= 32'h0000_0000;
`endif
	assign o_ipv4_fib_lut_rd_ipv4_net	=
		ipv4_fib_table_net[row_num_select];

	// ---------------------------------------------------------------------
	// Clocked work:
	// reset table or handle table reads and writes.
	always @(posedge Bus2IP_Clk) begin
		o_ipv4_fib_lut_rd_ack <= 0;
		o_ipv4_fib_lut_wr_ack <= 0;

		if (Bus2IP_Reset) begin
			for (i = 0; i < 32; i = i + 1) begin
				ipv4_fib_table_oif[i]  <= {8{1'b0}};
				ipv4_fib_table_nh[i]   <= {32{1'b0}};
`ifdef FIB_LOOKUP_FOR_LOOPS
				ipv4_fib_table_mask[i] <= {32{1'b1}};
`endif
				ipv4_fib_table_net[i]  <= {32{1'b0}};
			end
		end else begin
			if (i_ipv4_fib_lut_rd_req) begin
				row_num_select <= i_ipv4_fib_lut_rd_addr;
				o_ipv4_fib_lut_rd_ack <= 1;
			end else
			if (i_ipv4_fib_lut_wr_req) begin
				ipv4_fib_table_oif[i_ipv4_fib_lut_wr_addr]
					<= i_ipv4_fib_lut_wr_ipv4_oif[7:0];
				ipv4_fib_table_nh[i_ipv4_fib_lut_wr_addr]
					<= i_ipv4_fib_lut_wr_ipv4_nh;
`ifdef FIB_LOOKUP_FOR_LOOPS
				ipv4_fib_table_mask[i_ipv4_fib_lut_wr_addr]
					<= i_ipv4_fib_lut_wr_ipv4_mask;
				ipv4_fib_table_net[i_ipv4_fib_lut_wr_addr]
					<= i_ipv4_fib_lut_wr_ipv4_net &
					    i_ipv4_fib_lut_wr_ipv4_mask;
`else
				ipv4_fib_table_net[i_ipv4_fib_lut_wr_addr]
					<= i_ipv4_fib_lut_wr_ipv4_net;
				r_ipv4_fib_mask <= i_ipv4_fib_lut_wr_ipv4_mask;
				r_ipv4_fib_idx <= i_ipv4_fib_lut_wr_addr;
`endif
				o_ipv4_fib_lut_wr_ack <= 1;
			end
		end
	end

`ifndef FIB_LOOKUP_FOR_LOOPS
	// Update the encoding.  The temporary registers are a it hackerish
	// but this should never exceed one clock cycle anyway.
	always @(
		r_ipv4_fib_mask, i_ipv4_fib_lut_wr_addr,
		ipv4_fib_table_net[0], ipv4_fib_table_net[16],
		ipv4_fib_table_net[1], ipv4_fib_table_net[17],
		ipv4_fib_table_net[2], ipv4_fib_table_net[18],
		ipv4_fib_table_net[3], ipv4_fib_table_net[19],
		ipv4_fib_table_net[4], ipv4_fib_table_net[20],
		ipv4_fib_table_net[5], ipv4_fib_table_net[21],
		ipv4_fib_table_net[6], ipv4_fib_table_net[22],
		ipv4_fib_table_net[7], ipv4_fib_table_net[23],
		ipv4_fib_table_net[8], ipv4_fib_table_net[24],
		ipv4_fib_table_net[9], ipv4_fib_table_net[25],
		ipv4_fib_table_net[10], ipv4_fib_table_net[26],
		ipv4_fib_table_net[11], ipv4_fib_table_net[27],
		ipv4_fib_table_net[12], ipv4_fib_table_net[28],
		ipv4_fib_table_net[13], ipv4_fib_table_net[29],
		ipv4_fib_table_net[14], ipv4_fib_table_net[30],
		ipv4_fib_table_net[15], ipv4_fib_table_net[31]
	) begin
		for (z = 0; z < 32; z = z + 1) begin
			if (!r_ipv4_fib_mask[z]) begin
				ipv4_fib_table_net[r_ipv4_fib_idx][z] = 1'bx;
			end
		end
	end
`endif

	// ---------------------------------------------------------------------
	// Do our table lookup without considering that it might be updated
	// for the moment.

	// ---------------------------------------------------------------------
`ifdef FIB_LOOKUP_FOR_LOOPS
	reg					r_found_s1, r_found_s2;
	reg					r_found_s3, r_found_s4;
	reg [31:0]				r_nh_s1, r_nh_s2;
	reg [31:0]				r_nh_s3, r_nh_s4;
	reg [7:0]				r_tuser_s1, r_tuser_s2;
	reg [7:0]				r_tuser_s3, r_tuser_s4;
`else
	// One extra bit for ``invalid'' (not found and default) state.
`ifdef FIB_LOOKUP_HSIMPLE
	reg [40:0]				r_found;
`else
	reg [40:0]				r_found_h1, r_found_h2;
`endif
`endif
	reg					r_ipv4_fib_lut_nh_found;
	reg [7:0]				r_ipv4_fib_lut_tuser;

`ifdef FIB_LOOKUP_FOR_LOOPS
	integer					j, k, l, m;
`endif

	// Birds on the wire.
	wire [31:0]				w_daddr;
	wire					w_ipv4_fib_lut_out_empty;
`ifdef FIB_LOOKUP_FOR_LOOPS
	wire [3:0]				w_found;

	// Spaghetti.
	assign					w_found =
	    (r_found_s4 << 3) | (r_found_s3 << 2) | (r_found_s2 << 1) | r_found_s1;
`endif
	assign					w_daddr = i_ipv4_fib_lut_daddr;
	assign					o_ipv4_fib_lut_valid = !w_ipv4_fib_lut_out_empty;

	// ---------------------------------------------------------------------
	// FIFO.
	fallthrough_small_fifo
	#(
`ifdef NOT_DISABLE_UNSUED
		.WIDTH(1 + 32 + 8),
`else
		.WIDTH(1 + 8),
`endif
		.MAX_DEPTH_BITS(2)
	) ipv4_fib_lut_out
	// inputs and outputs
	(
		// Inputs
		.clk		(clk),
		.reset		(reset),
`ifdef NOT_DISABLE_UNSUED
		.din		({r_ipv4_fib_lut_nh_found, o_im_ipv4_fib_lut_nh, r_ipv4_fib_lut_tuser}),
`else
		.din		({r_ipv4_fib_lut_nh_found, r_ipv4_fib_lut_tuser}),
`endif
		.rd_en		(i_rd_from_magic),
		.wr_en		(o_im_ipv4_fib_lut_valid),
		// Outputs
`ifdef NOT_DISABLE_UNSUED
		.dout		({o_ipv4_fib_lut_nh_found, o_ipv4_fib_lut_nh, o_ipv4_fib_lut_tuser}),
`else
		.dout		({o_ipv4_fib_lut_nh_found, o_ipv4_fib_lut_tuser}),
`endif
		.full		(),
		.nearly_full	(),
		.prog_full	(),
		.empty		(w_ipv4_fib_lut_out_empty)
	);

`ifdef FIB_LOOKUP_FOR_LOOPS
	// ---------------------------------------------------------------------
	// Do the table lookup in parallellellell.
	always @(
		w_daddr, i_ipv4_fib_lut_daddr, i_ipv4_fib_lut_daddr_valid,
		ipv4_fib_table_nh[0], ipv4_fib_table_oif[0],
		ipv4_fib_table_nh[1], ipv4_fib_table_oif[1],
		ipv4_fib_table_nh[2], ipv4_fib_table_oif[2],
		ipv4_fib_table_nh[3], ipv4_fib_table_oif[3],
		ipv4_fib_table_nh[4], ipv4_fib_table_oif[4],
		ipv4_fib_table_nh[5], ipv4_fib_table_oif[5],
		ipv4_fib_table_nh[6], ipv4_fib_table_oif[6],
		ipv4_fib_table_nh[7], ipv4_fib_table_oif[7],
		ipv4_fib_table_net[0], ipv4_fib_table_mask[0],
		ipv4_fib_table_net[1], ipv4_fib_table_mask[1],
		ipv4_fib_table_net[2], ipv4_fib_table_mask[2],
		ipv4_fib_table_net[3], ipv4_fib_table_mask[3],
		ipv4_fib_table_net[4], ipv4_fib_table_mask[4],
		ipv4_fib_table_net[5], ipv4_fib_table_mask[5],
		ipv4_fib_table_net[6], ipv4_fib_table_mask[6],
		ipv4_fib_table_net[7], ipv4_fib_table_mask[7]
	) begin
		r_found_s1 = 0;
		r_nh_s1 = 32'h00000000;
		r_tuser_s1 = 8'h00;

		if (i_ipv4_fib_lut_daddr_valid) begin
			for (j = 0; j < 8; j = j + 1) begin
				if (!r_found_s1 &&
				    ipv4_fib_table_net[j] ==
				    (w_daddr & ipv4_fib_table_mask[j])) begin
					r_found_s1 = 1;
					r_nh_s1 = ipv4_fib_table_nh[j];
					r_tuser_s1 = ipv4_fib_table_oif[j];
				end
			end
		end
	end

	always @(
		w_daddr, i_ipv4_fib_lut_daddr, i_ipv4_fib_lut_daddr_valid,
		ipv4_fib_table_nh[8], ipv4_fib_table_oif[8],
		ipv4_fib_table_nh[9], ipv4_fib_table_oif[9],
		ipv4_fib_table_nh[10], ipv4_fib_table_oif[10],
		ipv4_fib_table_nh[11], ipv4_fib_table_oif[11],
		ipv4_fib_table_nh[12], ipv4_fib_table_oif[12],
		ipv4_fib_table_nh[13], ipv4_fib_table_oif[13],
		ipv4_fib_table_nh[14], ipv4_fib_table_oif[14],
		ipv4_fib_table_nh[15], ipv4_fib_table_oif[15],
		ipv4_fib_table_net[8], ipv4_fib_table_mask[8],
		ipv4_fib_table_net[9], ipv4_fib_table_mask[9],
		ipv4_fib_table_net[10], ipv4_fib_table_mask[10],
		ipv4_fib_table_net[11], ipv4_fib_table_mask[11],
		ipv4_fib_table_net[12], ipv4_fib_table_mask[12],
		ipv4_fib_table_net[13], ipv4_fib_table_mask[13],
		ipv4_fib_table_net[14], ipv4_fib_table_mask[14],
		ipv4_fib_table_net[15], ipv4_fib_table_mask[15]
	) begin
		r_found_s2 = 0;
		r_nh_s2 = 32'h00000000;
		r_tuser_s2 = 8'h00;

		if (i_ipv4_fib_lut_daddr_valid) begin
			for (k = 8; k < 16; k = k + 1) begin
				if (!r_found_s2 &&
				    ipv4_fib_table_net[k] ==
				    (w_daddr & ipv4_fib_table_mask[k])) begin
					r_found_s2 = 1;
					r_nh_s2 = ipv4_fib_table_nh[k];
					r_tuser_s2 = ipv4_fib_table_oif[k];
				end
			end
		end
	end


	always @(
		w_daddr, i_ipv4_fib_lut_daddr, i_ipv4_fib_lut_daddr_valid,
		ipv4_fib_table_nh[16], ipv4_fib_table_oif[16],
		ipv4_fib_table_nh[17], ipv4_fib_table_oif[17],
		ipv4_fib_table_nh[18], ipv4_fib_table_oif[18],
		ipv4_fib_table_nh[19], ipv4_fib_table_oif[19],
		ipv4_fib_table_nh[20], ipv4_fib_table_oif[20],
		ipv4_fib_table_nh[21], ipv4_fib_table_oif[21],
		ipv4_fib_table_nh[22], ipv4_fib_table_oif[22],
		ipv4_fib_table_nh[23], ipv4_fib_table_oif[23],
		ipv4_fib_table_net[16], ipv4_fib_table_mask[16],
		ipv4_fib_table_net[17], ipv4_fib_table_mask[17],
		ipv4_fib_table_net[18], ipv4_fib_table_mask[18],
		ipv4_fib_table_net[19], ipv4_fib_table_mask[19],
		ipv4_fib_table_net[20], ipv4_fib_table_mask[20],
		ipv4_fib_table_net[21], ipv4_fib_table_mask[21],
		ipv4_fib_table_net[22], ipv4_fib_table_mask[22],
		ipv4_fib_table_net[23], ipv4_fib_table_mask[23]
	) begin
		r_found_s3 = 0;
		r_nh_s3 = 32'h00000000;
		r_tuser_s3 = 8'h00;

		if (i_ipv4_fib_lut_daddr_valid) begin
			for (l = 16; l < 24; l = l + 1) begin
				if (!r_found_s3 &&
				    ipv4_fib_table_net[l] ==
				    (w_daddr & ipv4_fib_table_mask[l])) begin
					r_found_s3 = 1;
					r_nh_s3 = ipv4_fib_table_nh[l];
					r_tuser_s3 = ipv4_fib_table_oif[l];
				end
			end
		end
	end


	always @(
		w_daddr, i_ipv4_fib_lut_daddr, i_ipv4_fib_lut_daddr_valid,
		ipv4_fib_table_nh[24], ipv4_fib_table_oif[24],
		ipv4_fib_table_nh[25], ipv4_fib_table_oif[25],
		ipv4_fib_table_nh[26], ipv4_fib_table_oif[26],
		ipv4_fib_table_nh[27], ipv4_fib_table_oif[27],
		ipv4_fib_table_nh[28], ipv4_fib_table_oif[28],
		ipv4_fib_table_nh[29], ipv4_fib_table_oif[29],
		ipv4_fib_table_nh[30], ipv4_fib_table_oif[30],
		ipv4_fib_table_nh[31], ipv4_fib_table_oif[31],
		ipv4_fib_table_net[24], ipv4_fib_table_mask[24],
		ipv4_fib_table_net[25], ipv4_fib_table_mask[25],
		ipv4_fib_table_net[26], ipv4_fib_table_mask[26],
		ipv4_fib_table_net[27], ipv4_fib_table_mask[27],
		ipv4_fib_table_net[28], ipv4_fib_table_mask[28],
		ipv4_fib_table_net[29], ipv4_fib_table_mask[29],
		ipv4_fib_table_net[30], ipv4_fib_table_mask[30],
		ipv4_fib_table_net[31], ipv4_fib_table_mask[31]
	) begin
		r_found_s4 = 0;
		r_nh_s4 = 32'h00000000;
		r_tuser_s4 = 8'h00;

		if (i_ipv4_fib_lut_daddr_valid) begin
			for (m = 24; m < 32; m = m + 1) begin
				if (!r_found_s4 &&
				    ipv4_fib_table_net[m] ==
				    (w_daddr & ipv4_fib_table_mask[m])) begin
					r_found_s4 = 1;
					r_nh_s4 = ipv4_fib_table_nh[m];
					r_tuser_s4 = ipv4_fib_table_oif[m];
				end
			end
		end
	end
`else
`ifdef FIB_LOOKUP_HSIMPLE
	always @(
		w_daddr, i_ipv4_fib_lut_daddr_valid,
		ipv4_fib_table_net[0], ipv4_fib_table_net[16],
		ipv4_fib_table_net[1], ipv4_fib_table_net[17],
		ipv4_fib_table_net[2], ipv4_fib_table_net[18],
		ipv4_fib_table_net[3], ipv4_fib_table_net[19],
		ipv4_fib_table_net[4], ipv4_fib_table_net[20],
		ipv4_fib_table_net[5], ipv4_fib_table_net[21],
		ipv4_fib_table_net[6], ipv4_fib_table_net[22],
		ipv4_fib_table_net[7], ipv4_fib_table_net[23],
		ipv4_fib_table_net[8], ipv4_fib_table_net[24],
		ipv4_fib_table_net[9], ipv4_fib_table_net[25],
		ipv4_fib_table_net[10], ipv4_fib_table_net[26],
		ipv4_fib_table_net[11], ipv4_fib_table_net[27],
		ipv4_fib_table_net[12], ipv4_fib_table_net[28],
		ipv4_fib_table_net[13], ipv4_fib_table_net[29],
		ipv4_fib_table_net[14], ipv4_fib_table_net[30],
		ipv4_fib_table_net[15], ipv4_fib_table_net[31],
		ipv4_fib_table_nh[0], ipv4_fib_table_nh[16],
		ipv4_fib_table_nh[1], ipv4_fib_table_nh[17],
		ipv4_fib_table_nh[2], ipv4_fib_table_nh[18],
		ipv4_fib_table_nh[3], ipv4_fib_table_nh[19],
		ipv4_fib_table_nh[4], ipv4_fib_table_nh[20],
		ipv4_fib_table_nh[5], ipv4_fib_table_nh[21],
		ipv4_fib_table_nh[6], ipv4_fib_table_nh[22],
		ipv4_fib_table_nh[7], ipv4_fib_table_nh[23],
		ipv4_fib_table_nh[8], ipv4_fib_table_nh[24],
		ipv4_fib_table_nh[9], ipv4_fib_table_nh[25],
		ipv4_fib_table_nh[10], ipv4_fib_table_nh[26],
		ipv4_fib_table_nh[11], ipv4_fib_table_nh[27],
		ipv4_fib_table_nh[12], ipv4_fib_table_nh[28],
		ipv4_fib_table_nh[13], ipv4_fib_table_nh[29],
		ipv4_fib_table_nh[14], ipv4_fib_table_nh[30],
		ipv4_fib_table_nh[15], ipv4_fib_table_nh[31],
		ipv4_fib_table_oif[0], ipv4_fib_table_oif[16],
		ipv4_fib_table_oif[1], ipv4_fib_table_oif[17],
		ipv4_fib_table_oif[2], ipv4_fib_table_oif[18],
		ipv4_fib_table_oif[3], ipv4_fib_table_oif[19],
		ipv4_fib_table_oif[4], ipv4_fib_table_oif[20],
		ipv4_fib_table_oif[5], ipv4_fib_table_oif[21],
		ipv4_fib_table_oif[6], ipv4_fib_table_oif[22],
		ipv4_fib_table_oif[7], ipv4_fib_table_oif[23],
		ipv4_fib_table_oif[8], ipv4_fib_table_oif[24],
		ipv4_fib_table_oif[9], ipv4_fib_table_oif[25],
		ipv4_fib_table_oif[10], ipv4_fib_table_oif[26],
		ipv4_fib_table_oif[11], ipv4_fib_table_oif[27],
		ipv4_fib_table_oif[12], ipv4_fib_table_oif[28],
		ipv4_fib_table_oif[13], ipv4_fib_table_oif[29],
		ipv4_fib_table_oif[14], ipv4_fib_table_oif[30],
		ipv4_fib_table_oif[15], ipv4_fib_table_oif[31]
	) begin
		r_found = {40{1'b0}};

		if (i_ipv4_fib_lut_daddr_valid) begin
			// XXX-BZ this screams for a generate statement
			casex (w_daddr)
			ipv4_fib_table_net[0]:
				r_found = {1'b1, ipv4_fib_table_oif[0], ipv4_fib_table_nh[0]};
			ipv4_fib_table_net[1]:
				r_found = {1'b1, ipv4_fib_table_oif[1], ipv4_fib_table_nh[1]};
			ipv4_fib_table_net[2]:
				r_found = {1'b1, ipv4_fib_table_oif[2], ipv4_fib_table_nh[2]};
			ipv4_fib_table_net[3]:
				r_found = {1'b1, ipv4_fib_table_oif[3], ipv4_fib_table_nh[3]};
			ipv4_fib_table_net[4]:
				r_found = {1'b1, ipv4_fib_table_oif[4], ipv4_fib_table_nh[4]};
			ipv4_fib_table_net[5]:
				r_found = {1'b1, ipv4_fib_table_oif[5], ipv4_fib_table_nh[5]};
			ipv4_fib_table_net[6]:
				r_found = {1'b1, ipv4_fib_table_oif[6], ipv4_fib_table_nh[6]};
			ipv4_fib_table_net[7]:
				r_found = {1'b1, ipv4_fib_table_oif[7], ipv4_fib_table_nh[7]};
			ipv4_fib_table_net[8]:
				r_found = {1'b1, ipv4_fib_table_oif[8], ipv4_fib_table_nh[8]};
			ipv4_fib_table_net[9]:
				r_found = {1'b1, ipv4_fib_table_oif[9], ipv4_fib_table_nh[9]};
			ipv4_fib_table_net[10]:
				r_found = {1'b1, ipv4_fib_table_oif[10], ipv4_fib_table_nh[10]};
			ipv4_fib_table_net[11]:
				r_found = {1'b1, ipv4_fib_table_oif[11], ipv4_fib_table_nh[11]};
			ipv4_fib_table_net[12]:
				r_found = {1'b1, ipv4_fib_table_oif[12], ipv4_fib_table_nh[12]};
			ipv4_fib_table_net[13]:
				r_found = {1'b1, ipv4_fib_table_oif[13], ipv4_fib_table_nh[13]};
			ipv4_fib_table_net[14]:
				r_found = {1'b1, ipv4_fib_table_oif[14], ipv4_fib_table_nh[14]};
			ipv4_fib_table_net[15]:
				r_found = {1'b1, ipv4_fib_table_oif[15], ipv4_fib_table_nh[15]};
			ipv4_fib_table_net[16]:
				r_found = {1'b1, ipv4_fib_table_oif[16], ipv4_fib_table_nh[16]};
			ipv4_fib_table_net[17]:
				r_found = {1'b1, ipv4_fib_table_oif[17], ipv4_fib_table_nh[17]};
			ipv4_fib_table_net[18]:
				r_found = {1'b1, ipv4_fib_table_oif[18], ipv4_fib_table_nh[18]};
			ipv4_fib_table_net[19]:
				r_found = {1'b1, ipv4_fib_table_oif[19], ipv4_fib_table_nh[19]};
			ipv4_fib_table_net[20]:
				r_found = {1'b1, ipv4_fib_table_oif[20], ipv4_fib_table_nh[20]};
			ipv4_fib_table_net[21]:
				r_found = {1'b1, ipv4_fib_table_oif[21], ipv4_fib_table_nh[21]};
			ipv4_fib_table_net[22]:
				r_found = {1'b1, ipv4_fib_table_oif[22], ipv4_fib_table_nh[22]};
			ipv4_fib_table_net[23]:
				r_found = {1'b1, ipv4_fib_table_oif[23], ipv4_fib_table_nh[23]};
			ipv4_fib_table_net[24]:
				r_found = {1'b1, ipv4_fib_table_oif[24], ipv4_fib_table_nh[24]};
			ipv4_fib_table_net[25]:
				r_found = {1'b1, ipv4_fib_table_oif[25], ipv4_fib_table_nh[25]};
			ipv4_fib_table_net[26]:
				r_found = {1'b1, ipv4_fib_table_oif[26], ipv4_fib_table_nh[26]};
			ipv4_fib_table_net[27]:
				r_found = {1'b1, ipv4_fib_table_oif[27], ipv4_fib_table_nh[27]};
			ipv4_fib_table_net[28]:
				r_found = {1'b1, ipv4_fib_table_oif[28], ipv4_fib_table_nh[28]};
			ipv4_fib_table_net[29]:
				r_found = {1'b1, ipv4_fib_table_oif[29], ipv4_fib_table_nh[29]};
			ipv4_fib_table_net[30]:
				r_found = {1'b1, ipv4_fib_table_oif[30], ipv4_fib_table_nh[30]};
			ipv4_fib_table_net[31]:
				r_found = {1'b1, ipv4_fib_table_oif[31], ipv4_fib_table_nh[31]};
			default: r_found = {40{1'b0}};
			endcase
		end
	end
`else
	always @(
		w_daddr, i_ipv4_fib_lut_daddr_valid,
		ipv4_fib_table_net[0], ipv4_fib_table_net[1],
		ipv4_fib_table_net[2], ipv4_fib_table_net[3],
		ipv4_fib_table_net[4], ipv4_fib_table_net[5],
		ipv4_fib_table_net[6], ipv4_fib_table_net[7],
		ipv4_fib_table_net[8], ipv4_fib_table_net[9],
		ipv4_fib_table_net[10], ipv4_fib_table_net[11],
		ipv4_fib_table_net[12], ipv4_fib_table_net[13],
		ipv4_fib_table_net[14], ipv4_fib_table_net[15],
		ipv4_fib_table_nh[0], ipv4_fib_table_nh[1],
		ipv4_fib_table_nh[2], ipv4_fib_table_nh[3],
		ipv4_fib_table_nh[4], ipv4_fib_table_nh[5],
		ipv4_fib_table_nh[6], ipv4_fib_table_nh[7],
		ipv4_fib_table_nh[8], ipv4_fib_table_nh[9],
		ipv4_fib_table_nh[10], ipv4_fib_table_nh[11],
		ipv4_fib_table_nh[12], ipv4_fib_table_nh[13],
		ipv4_fib_table_nh[14], ipv4_fib_table_nh[15],
		ipv4_fib_table_oif[0], ipv4_fib_table_oif[1],
		ipv4_fib_table_oif[2], ipv4_fib_table_oif[3],
		ipv4_fib_table_oif[4], ipv4_fib_table_oif[5],
		ipv4_fib_table_oif[6], ipv4_fib_table_oif[7],
		ipv4_fib_table_oif[8], ipv4_fib_table_oif[9],
		ipv4_fib_table_oif[10], ipv4_fib_table_oif[11],
		ipv4_fib_table_oif[12], ipv4_fib_table_oif[13],
		ipv4_fib_table_oif[14], ipv4_fib_table_oif[15]
	) begin
		r_found_h1 = {40{1'b0}};

		if (i_ipv4_fib_lut_daddr_valid) begin
			// XXX-BZ this screams for a generate statement
			casex (w_daddr)
			ipv4_fib_table_net[0]:
				r_found_h1 = {1'b1, ipv4_fib_table_oif[0], ipv4_fib_table_nh[0]};
			ipv4_fib_table_net[1]:
				r_found_h1 = {1'b1, ipv4_fib_table_oif[1], ipv4_fib_table_nh[1]};
			ipv4_fib_table_net[2]:
				r_found_h1 = {1'b1, ipv4_fib_table_oif[2], ipv4_fib_table_nh[2]};
			ipv4_fib_table_net[3]:
				r_found_h1 = {1'b1, ipv4_fib_table_oif[3], ipv4_fib_table_nh[3]};
			ipv4_fib_table_net[4]:
				r_found_h1 = {1'b1, ipv4_fib_table_oif[4], ipv4_fib_table_nh[4]};
			ipv4_fib_table_net[5]:
				r_found_h1 = {1'b1, ipv4_fib_table_oif[5], ipv4_fib_table_nh[5]};
			ipv4_fib_table_net[6]:
				r_found_h1 = {1'b1, ipv4_fib_table_oif[6], ipv4_fib_table_nh[6]};
			ipv4_fib_table_net[7]:
				r_found_h1 = {1'b1, ipv4_fib_table_oif[7], ipv4_fib_table_nh[7]};
			ipv4_fib_table_net[8]:
				r_found_h1 = {1'b1, ipv4_fib_table_oif[8], ipv4_fib_table_nh[8]};
			ipv4_fib_table_net[9]:
				r_found_h1 = {1'b1, ipv4_fib_table_oif[9], ipv4_fib_table_nh[9]};
			ipv4_fib_table_net[10]:
				r_found_h1 = {1'b1, ipv4_fib_table_oif[10], ipv4_fib_table_nh[10]};
			ipv4_fib_table_net[11]:
				r_found_h1 = {1'b1, ipv4_fib_table_oif[11], ipv4_fib_table_nh[11]};
			ipv4_fib_table_net[12]:
				r_found_h1 = {1'b1, ipv4_fib_table_oif[12], ipv4_fib_table_nh[12]};
			ipv4_fib_table_net[13]:
				r_found_h1 = {1'b1, ipv4_fib_table_oif[13], ipv4_fib_table_nh[13]};
			ipv4_fib_table_net[14]:
				r_found_h1 = {1'b1, ipv4_fib_table_oif[14], ipv4_fib_table_nh[14]};
			ipv4_fib_table_net[15]:
				r_found_h1 = {1'b1, ipv4_fib_table_oif[15], ipv4_fib_table_nh[15]};
			default:
				r_found_h1 = {40{1'b0}};
			endcase
		end
	end
	always @(
		w_daddr, i_ipv4_fib_lut_daddr_valid,
		ipv4_fib_table_net[16], ipv4_fib_table_net[17],
		ipv4_fib_table_net[18], ipv4_fib_table_net[19],
		ipv4_fib_table_net[20], ipv4_fib_table_net[21],
		ipv4_fib_table_net[22], ipv4_fib_table_net[23],
		ipv4_fib_table_net[24], ipv4_fib_table_net[25],
		ipv4_fib_table_net[26], ipv4_fib_table_net[27],
		ipv4_fib_table_net[28], ipv4_fib_table_net[29],
		ipv4_fib_table_net[30], ipv4_fib_table_net[31],
		ipv4_fib_table_nh[16], ipv4_fib_table_nh[17],
		ipv4_fib_table_nh[18], ipv4_fib_table_nh[19],
		ipv4_fib_table_nh[20], ipv4_fib_table_nh[21],
		ipv4_fib_table_nh[22], ipv4_fib_table_nh[23],
		ipv4_fib_table_nh[24], ipv4_fib_table_nh[25],
		ipv4_fib_table_nh[26], ipv4_fib_table_nh[27],
		ipv4_fib_table_nh[28], ipv4_fib_table_nh[29],
		ipv4_fib_table_nh[30], ipv4_fib_table_nh[31],
		ipv4_fib_table_oif[16], ipv4_fib_table_oif[17],
		ipv4_fib_table_oif[18], ipv4_fib_table_oif[19],
		ipv4_fib_table_oif[20], ipv4_fib_table_oif[21],
		ipv4_fib_table_oif[22], ipv4_fib_table_oif[23],
		ipv4_fib_table_oif[24], ipv4_fib_table_oif[25],
		ipv4_fib_table_oif[26], ipv4_fib_table_oif[27],
		ipv4_fib_table_oif[28], ipv4_fib_table_oif[29],
		ipv4_fib_table_oif[30], ipv4_fib_table_oif[31]
	) begin
		r_found_h2 = {40{1'b0}};

		if (i_ipv4_fib_lut_daddr_valid) begin
			// XXX-BZ this screams for a generate statement
			casex (w_daddr)
			ipv4_fib_table_net[16]:
				r_found_h2 = {1'b1, ipv4_fib_table_oif[16], ipv4_fib_table_nh[16]};
			ipv4_fib_table_net[17]:
				r_found_h2 = {1'b1, ipv4_fib_table_oif[17], ipv4_fib_table_nh[17]};
			ipv4_fib_table_net[18]:
				r_found_h2 = {1'b1, ipv4_fib_table_oif[18], ipv4_fib_table_nh[18]};
			ipv4_fib_table_net[19]:
				r_found_h2 = {1'b1, ipv4_fib_table_oif[19], ipv4_fib_table_nh[19]};
			ipv4_fib_table_net[20]:
				r_found_h2 = {1'b1, ipv4_fib_table_oif[20], ipv4_fib_table_nh[20]};
			ipv4_fib_table_net[21]:
				r_found_h2 = {1'b1, ipv4_fib_table_oif[21], ipv4_fib_table_nh[21]};
			ipv4_fib_table_net[22]:
				r_found_h2 = {1'b1, ipv4_fib_table_oif[22], ipv4_fib_table_nh[22]};
			ipv4_fib_table_net[23]:
				r_found_h2 = {1'b1, ipv4_fib_table_oif[23], ipv4_fib_table_nh[23]};
			ipv4_fib_table_net[24]:
				r_found_h2 = {1'b1, ipv4_fib_table_oif[24], ipv4_fib_table_nh[24]};
			ipv4_fib_table_net[25]:
				r_found_h2 = {1'b1, ipv4_fib_table_oif[25], ipv4_fib_table_nh[25]};
			ipv4_fib_table_net[26]:
				r_found_h2 = {1'b1, ipv4_fib_table_oif[26], ipv4_fib_table_nh[26]};
			ipv4_fib_table_net[27]:
				r_found_h2 = {1'b1, ipv4_fib_table_oif[27], ipv4_fib_table_nh[27]};
			ipv4_fib_table_net[28]:
				r_found_h2 = {1'b1, ipv4_fib_table_oif[28], ipv4_fib_table_nh[28]};
			ipv4_fib_table_net[29]:
				r_found_h2 = {1'b1, ipv4_fib_table_oif[29], ipv4_fib_table_nh[29]};
			ipv4_fib_table_net[30]:
				r_found_h2 = {1'b1, ipv4_fib_table_oif[30], ipv4_fib_table_nh[30]};
			ipv4_fib_table_net[31]:
				r_found_h2 = {1'b1, ipv4_fib_table_oif[31], ipv4_fib_table_nh[31]};
			default:
				r_found_h2 = {40{1'b0}};
			endcase
		end
	end
`endif
`endif

	// ---------------------------------------------------------------------
	// Clocked work:
	always @(posedge clk) begin

		if (reset) begin
			r_ipv4_fib_lut_nh_found <= 0;
			o_im_ipv4_fib_lut_nh <= 32'h00000000;
			r_ipv4_fib_lut_tuser <= 8'h00;
			o_im_ipv4_fib_lut_valid <= 0;

		end else begin
			if (i_ipv4_fib_lut_daddr_valid) begin
`ifdef FIB_LOOKUP_FOR_LOOPS
				casex (w_found)
				4'bxxx1: begin
					r_ipv4_fib_lut_nh_found <= 1;
					o_im_ipv4_fib_lut_nh <= r_nh_s1;
					r_ipv4_fib_lut_tuser <= r_tuser_s1;
				end
				4'bxx1x: begin
					r_ipv4_fib_lut_nh_found <= 1;
					o_im_ipv4_fib_lut_nh <= r_nh_s2;
					r_ipv4_fib_lut_tuser <= r_tuser_s2;
				end
				4'bx1xx: begin
					r_ipv4_fib_lut_nh_found <= 1;
					o_im_ipv4_fib_lut_nh <= r_nh_s3;
					r_ipv4_fib_lut_tuser <= r_tuser_s3;
				end
				4'b1xxx: begin
					r_ipv4_fib_lut_nh_found <= 1;
					o_im_ipv4_fib_lut_nh <= r_nh_s4;
					r_ipv4_fib_lut_tuser <= r_tuser_s4;
				end
				default: begin
					r_ipv4_fib_lut_nh_found <= 0;
					o_im_ipv4_fib_lut_nh <= 32'h00000000;
					r_ipv4_fib_lut_tuser <= 8'h00;
				end
				endcase
				//if (r_ipv4_fib_lut_nh_found & !(|o_im_ipv4_fib_lut_nh))
				//	o_im_ipv4_fib_lut_nh <= i_ipv4_fib_lut_daddr;
`else
`ifdef FIB_LOOKUP_HSIMPLE
				o_im_ipv4_fib_lut_nh <= r_found[0+:32];
				r_ipv4_fib_lut_tuser <= r_found[32+:8];
				r_ipv4_fib_lut_nh_found <= r_found[40];
`else
				if (r_found_h1[40]) begin
					o_im_ipv4_fib_lut_nh <= r_found_h1[0+:32];
					r_ipv4_fib_lut_tuser <= r_found_h1[32+:8];
					r_ipv4_fib_lut_nh_found <= r_found_h1[40];
				end else begin
					o_im_ipv4_fib_lut_nh <= r_found_h2[0+:32];
					r_ipv4_fib_lut_tuser <= r_found_h2[32+:8];
					r_ipv4_fib_lut_nh_found <= r_found_h2[40];
				end
`endif
`endif
				o_im_ipv4_fib_lut_valid <= 1;
			end else begin
				r_ipv4_fib_lut_nh_found <= 0;
				o_im_ipv4_fib_lut_nh <= 32'h00000000;
				r_ipv4_fib_lut_tuser <= 8'h00;
				o_im_ipv4_fib_lut_valid <= 0;
			end
		end
	end

// -----------------------------------------------------------------------------

`undef FIB_LOOKUP_HSIMPLE

endmodule // ipv4_fib_lut
