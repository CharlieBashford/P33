/*-
 * Copyright (c) 2014, Bjoern A. Zeeb
 * All rights reserved.
 *
 * IPv4 ARP table.
 *
 * Lookup ethernet address for a given next hop.
 * Provide the interface to user space for updating the table.
 * 
 * Table layout:
 * 	32 bit IPv4 address, 
 * 	32 bit low  ether address
 * 	16 bit high ether address
 */
module ipv4_arp_lut
	// ---------------------------------------------------------------------
	#(
		parameter IPV4_ARP_LUT_ROWS=32,
		parameter IPV4_ARP_LUT_ROW_BITS=5,
		parameter MAC_WIDTH=48
	)
	// inputs and outputs
	(
		// Always need these; no special prefix.
		input				Bus2IP_Clk,
		input				Bus2IP_Reset,

		// Table management from the register interface/axi.
		// (Keep ordering as in ipif_table_regs.)
		input					i_ipv4_arp_lut_rd_req,
		output reg				o_ipv4_arp_lut_rd_ack,
		input [IPV4_ARP_LUT_ROW_BITS-1:0]	i_ipv4_arp_lut_rd_addr,
		output [MAC_WIDTH-1:0]			o_ipv4_arp_lut_rd_eth_addr,
		output [31:0]				o_ipv4_arp_lut_rd_ipv4_addr,
		input					i_ipv4_arp_lut_wr_req,
		output reg				o_ipv4_arp_lut_wr_ack,
		input [IPV4_ARP_LUT_ROW_BITS-1:0]	i_ipv4_arp_lut_wr_addr,
		// Keep the input aligned with register interface to avoid warning.
		//input [MAC_WIDTH-1:0]			i_ipv4_arp_lut_wr_eth_addr,
		input [64-1:0]				i_ipv4_arp_lut_wr_eth_addr,
		input [31:0]				i_ipv4_arp_lut_wr_ipv4_addr,

		// Always need these; no special prefix.
		input					clk,
		input					reset,

		// Trigger reads from state FIFO(s).
		input					i_rd_from_magic,
		// In-HW access for lookups.
		// Destination address to lookup.
		input					i_ipv4_arp_lut_ipv4_daddr_valid,	// IPv4
		input [31:0]				i_ipv4_arp_lut_ipv4_daddr,
		input					i_ipv4_arp_lut_fib_daddr_valid,		// FIB
		input [31:0]				i_ipv4_arp_lut_fib_daddr,
		// Is the address local?
		output					o_ipv4_arp_lut_ipv4_eth_addr_found,
		output [MAC_WIDTH-1:0]			o_ipv4_arp_lut_ipv4_eth_addr,
		output					o_ipv4_arp_lut_valid
	);

	// ---------------------------------------------------------------------
	// Definitions 
	//localparam	...			= ..;

	// Birds on wires..
	//wire	...				w_...;

	// Local register(s) to keep track of ...
	// 32 { IPv4 address entries (32 bit each), ether address (48 (64) bit))
	reg[MAC_WIDTH-1:0]	ipv4_arp_table_eth  [0:IPV4_ARP_LUT_ROWS-1];
	reg[31:0]		ipv4_arp_table_ipv4 [0:IPV4_ARP_LUT_ROWS-1];
	reg[IPV4_ARP_LUT_ROW_BITS-1:0]		row_num_select;

	integer					i;

	// Spaghetti.
	assign o_ipv4_arp_lut_rd_eth_addr	=
		ipv4_arp_table_eth[row_num_select];
	assign o_ipv4_arp_lut_rd_ipv4_addr	=
		ipv4_arp_table_ipv4[row_num_select];

	//assign o_ipv4_arp_lut_rd_ack		= i_ipv4_arp_lut_rd_req;
	//assign o_ipv4_arp_lut_wr_ack		= i_ipv4_arp_lut_wr_req;

	// ---------------------------------------------------------------------
	// Clocked work:
	// reset table or handle table reads and writes.
	always @(posedge Bus2IP_Clk) begin
		o_ipv4_arp_lut_rd_ack <= 0;
		o_ipv4_arp_lut_wr_ack <= 0;

		if (Bus2IP_Reset) begin
			for (i = 0; i < 32; i = i + 1) begin
				ipv4_arp_table_eth[i]  <= {MAC_WIDTH{1'b0}};
				ipv4_arp_table_ipv4[i] <= {32{1'b0}};
			end
		end else begin
			if (i_ipv4_arp_lut_rd_req) begin
				row_num_select <= i_ipv4_arp_lut_rd_addr;
				o_ipv4_arp_lut_rd_ack <= 1;
			end else
			if (i_ipv4_arp_lut_wr_req) begin
				ipv4_arp_table_eth[i_ipv4_arp_lut_wr_addr]
					<= i_ipv4_arp_lut_wr_eth_addr[MAC_WIDTH-1:0];
				ipv4_arp_table_ipv4[i_ipv4_arp_lut_wr_addr]
					<= i_ipv4_arp_lut_wr_ipv4_addr;
				o_ipv4_arp_lut_wr_ack <= 1;
			end
		end
	end

	// ---------------------------------------------------------------------
	// Do our table lookup without considering that it might be updated
	// for the moment.

	// ---------------------------------------------------------------------
`ifdef FIB_LOOKUP_FOR_LOOPS
	reg [MAC_WIDTH-1:0]			r_eaddr_s1, r_eaddr_s2;
	reg [MAC_WIDTH-1:0]			r_eaddr_s3, r_eaddr_s4;
	reg					r_found_s1, r_found_s2;
	reg					r_found_s3, r_found_s4;
`else
	// One extra bit for ``invalid'' (not found and default) state.
	reg [MAC_WIDTH:0]			r_found;
`endif
	reg					r_ipv4_arp_lut_out_wr_en;
	reg					r_ipv4_arp_lut_ipv4_eth_addr_found;
	reg [MAC_WIDTH-1:0]			r_ipv4_arp_lut_ipv4_eth_addr;
	reg [31:0]				r_ipv4_daddr;

`ifdef FIB_LOOKUP_FOR_LOOPS
	integer					j,k,l,m;
`endif

	// Birds on the wire.
	wire [31:0]				w_daddr;
	wire					w_ipv4_arp_lut_out_empty;
`ifdef FIB_LOOKUP_FOR_LOOPS
	wire [3:0]				w_found;
`endif
	wire					w_input_valid;

	// Spaghetti.
	assign					w_daddr = (|i_ipv4_arp_lut_fib_daddr) ? i_ipv4_arp_lut_fib_daddr : r_ipv4_daddr;
	assign					w_input_valid = i_ipv4_arp_lut_fib_daddr_valid & |w_daddr;
`ifdef FIB_LOOKUP_FOR_LOOPS
	assign					w_found =
	    (r_found_s4 << 3) | (r_found_s3 << 2) | (r_found_s2 << 1) | r_found_s1;
`endif
	assign					o_ipv4_arp_lut_valid = !w_ipv4_arp_lut_out_empty;

	// ---------------------------------------------------------------------
	// FIFO.
	fallthrough_small_fifo
	#(
		.WIDTH(1 + MAC_WIDTH),
		.MAX_DEPTH_BITS(2)
	) ipv4_arp_lut_out
	// inputs and outputs
	(
		// Inputs
		.clk		(clk),
		.reset		(reset),
		.din		({r_ipv4_arp_lut_ipv4_eth_addr_found, r_ipv4_arp_lut_ipv4_eth_addr}),
		.rd_en		(i_rd_from_magic),
		.wr_en		(r_ipv4_arp_lut_out_wr_en),
		// Outputs
		.dout		({o_ipv4_arp_lut_ipv4_eth_addr_found, o_ipv4_arp_lut_ipv4_eth_addr}),
		.full		(),
		.nearly_full	(),
		.prog_full	(),
		.empty		(w_ipv4_arp_lut_out_empty)
	);


	// ---------------------------------------------------------------------
	// Do the table lookup in parallellellell.
`ifdef FIB_LOOKUP_FOR_LOOPS
	always @(
		w_daddr, w_input_valid,
		ipv4_arp_table_eth[0], ipv4_arp_table_eth[1],
		ipv4_arp_table_eth[2], ipv4_arp_table_eth[3],
		ipv4_arp_table_eth[4], ipv4_arp_table_eth[5],
		ipv4_arp_table_eth[6], ipv4_arp_table_eth[7],
		ipv4_arp_table_ipv4[0], ipv4_arp_table_ipv4[1],
		ipv4_arp_table_ipv4[2], ipv4_arp_table_ipv4[3],
		ipv4_arp_table_ipv4[4], ipv4_arp_table_ipv4[5],
		ipv4_arp_table_ipv4[6], ipv4_arp_table_ipv4[7]
	) begin
		r_found_s1 = 0;
		r_eaddr_s1 = 48'h000000000000;
		if (w_input_valid) begin
			for (j = 0; j < 8; j = j + 1) begin
				if (!r_found_s1 &&
				    ipv4_arp_table_ipv4[j] == w_daddr)
				begin
					r_found_s1 = 1;
					r_eaddr_s1 = ipv4_arp_table_eth[j];
				end
			end
		end
	end

	always @(
		w_daddr, w_input_valid,
		ipv4_arp_table_eth[8], ipv4_arp_table_eth[9],
		ipv4_arp_table_eth[10], ipv4_arp_table_eth[11],
		ipv4_arp_table_eth[12], ipv4_arp_table_eth[13],
		ipv4_arp_table_eth[14], ipv4_arp_table_eth[15],
		ipv4_arp_table_ipv4[8], ipv4_arp_table_ipv4[9],
		ipv4_arp_table_ipv4[10], ipv4_arp_table_ipv4[11],
		ipv4_arp_table_ipv4[12], ipv4_arp_table_ipv4[13],
		ipv4_arp_table_ipv4[14], ipv4_arp_table_ipv4[15]
	) begin
		r_found_s2 = 0;
		r_eaddr_s2 = 48'h000000000000;
		if (w_input_valid) begin
			for (k = 8; k < 16; k = k + 1) begin
				if (!r_found_s2 &&
				    ipv4_arp_table_ipv4[k] == w_daddr)
				begin
					r_found_s2 = 1;
					r_eaddr_s2 = ipv4_arp_table_eth[k];
				end
			end
		end
	end

	always @(
		w_daddr, w_input_valid,
		ipv4_arp_table_eth[16], ipv4_arp_table_eth[17],
		ipv4_arp_table_eth[18], ipv4_arp_table_eth[19],
		ipv4_arp_table_eth[20], ipv4_arp_table_eth[21],
		ipv4_arp_table_eth[22], ipv4_arp_table_eth[23],
		ipv4_arp_table_ipv4[16], ipv4_arp_table_ipv4[17],
		ipv4_arp_table_ipv4[18], ipv4_arp_table_ipv4[19],
		ipv4_arp_table_ipv4[20], ipv4_arp_table_ipv4[21],
		ipv4_arp_table_ipv4[22], ipv4_arp_table_ipv4[23]
	) begin
		r_found_s3 = 0;
		r_eaddr_s3 = 48'h000000000000;
		if (w_input_valid) begin
			for (l = 16; l < 24; l = l + 1) begin
				if (!r_found_s3 &&
				    ipv4_arp_table_ipv4[l] == w_daddr)
				begin
					r_found_s3 = 1;
					r_eaddr_s3 = ipv4_arp_table_eth[l];
				end
			end
		end
	end

	always @(
		w_daddr, w_input_valid,
		ipv4_arp_table_eth[24], ipv4_arp_table_eth[25],
		ipv4_arp_table_eth[26], ipv4_arp_table_eth[27],
		ipv4_arp_table_eth[28], ipv4_arp_table_eth[29],
		ipv4_arp_table_eth[30], ipv4_arp_table_eth[31],
		ipv4_arp_table_ipv4[24], ipv4_arp_table_ipv4[25],
		ipv4_arp_table_ipv4[26], ipv4_arp_table_ipv4[27],
		ipv4_arp_table_ipv4[28], ipv4_arp_table_ipv4[29],
		ipv4_arp_table_ipv4[30], ipv4_arp_table_ipv4[31]
	) begin
		r_found_s4 = 0;
		r_eaddr_s4 = 48'h000000000000;
		if (w_input_valid) begin
			for (m = 24; m < 32; m = m + 1) begin
				if (!r_found_s4 &&
				    ipv4_arp_table_ipv4[m] == w_daddr)
				begin
					r_found_s4 = 1;
					r_eaddr_s4 = ipv4_arp_table_eth[m];
				end
			end
		end
	end
`else
	always @(
		w_daddr, w_input_valid,
		ipv4_arp_table_eth[0], ipv4_arp_table_eth[1],
		ipv4_arp_table_eth[2], ipv4_arp_table_eth[3],
		ipv4_arp_table_eth[4], ipv4_arp_table_eth[5],
		ipv4_arp_table_eth[6], ipv4_arp_table_eth[7],
		ipv4_arp_table_eth[8], ipv4_arp_table_eth[9],
		ipv4_arp_table_eth[10], ipv4_arp_table_eth[11],
		ipv4_arp_table_eth[12], ipv4_arp_table_eth[13],
		ipv4_arp_table_eth[14], ipv4_arp_table_eth[15],
		ipv4_arp_table_eth[16], ipv4_arp_table_eth[17],
		ipv4_arp_table_eth[18], ipv4_arp_table_eth[19],
		ipv4_arp_table_eth[20], ipv4_arp_table_eth[21],
		ipv4_arp_table_eth[22], ipv4_arp_table_eth[23],
		ipv4_arp_table_eth[24], ipv4_arp_table_eth[25],
		ipv4_arp_table_eth[26], ipv4_arp_table_eth[27],
		ipv4_arp_table_eth[28], ipv4_arp_table_eth[29],
		ipv4_arp_table_eth[30], ipv4_arp_table_eth[31],
		ipv4_arp_table_ipv4[0], ipv4_arp_table_ipv4[1],
		ipv4_arp_table_ipv4[2], ipv4_arp_table_ipv4[3],
		ipv4_arp_table_ipv4[4], ipv4_arp_table_ipv4[5],
		ipv4_arp_table_ipv4[6], ipv4_arp_table_ipv4[7],
		ipv4_arp_table_ipv4[8], ipv4_arp_table_ipv4[9],
		ipv4_arp_table_ipv4[10], ipv4_arp_table_ipv4[11],
		ipv4_arp_table_ipv4[12], ipv4_arp_table_ipv4[13],
		ipv4_arp_table_ipv4[14], ipv4_arp_table_ipv4[15],
		ipv4_arp_table_ipv4[16], ipv4_arp_table_ipv4[17],
		ipv4_arp_table_ipv4[18], ipv4_arp_table_ipv4[19],
		ipv4_arp_table_ipv4[20], ipv4_arp_table_ipv4[21],
		ipv4_arp_table_ipv4[22], ipv4_arp_table_ipv4[23],
		ipv4_arp_table_ipv4[24], ipv4_arp_table_ipv4[25],
		ipv4_arp_table_ipv4[26], ipv4_arp_table_ipv4[27],
		ipv4_arp_table_ipv4[28], ipv4_arp_table_ipv4[29],
		ipv4_arp_table_ipv4[30], ipv4_arp_table_ipv4[31]
	) begin
		r_found = { (1+MAC_WIDTH){40'b0} };

		if (w_input_valid) begin
			case (w_daddr)
			ipv4_arp_table_ipv4[0]: r_found = { 1'b1, ipv4_arp_table_eth[0] };
			ipv4_arp_table_ipv4[1]: r_found = { 1'b1, ipv4_arp_table_eth[1] };
			ipv4_arp_table_ipv4[2]: r_found = { 1'b1, ipv4_arp_table_eth[2] };
			ipv4_arp_table_ipv4[3]: r_found = { 1'b1, ipv4_arp_table_eth[3] };
			ipv4_arp_table_ipv4[4]: r_found = { 1'b1, ipv4_arp_table_eth[4] };
			ipv4_arp_table_ipv4[5]: r_found = { 1'b1, ipv4_arp_table_eth[5] };
			ipv4_arp_table_ipv4[6]: r_found = { 1'b1, ipv4_arp_table_eth[6] };
			ipv4_arp_table_ipv4[7]: r_found = { 1'b1, ipv4_arp_table_eth[7] };
			ipv4_arp_table_ipv4[8]: r_found = { 1'b1, ipv4_arp_table_eth[8] };
			ipv4_arp_table_ipv4[9]: r_found = { 1'b1, ipv4_arp_table_eth[9] };
			ipv4_arp_table_ipv4[10]: r_found = { 1'b1, ipv4_arp_table_eth[10] };
			ipv4_arp_table_ipv4[11]: r_found = { 1'b1, ipv4_arp_table_eth[11] };
			ipv4_arp_table_ipv4[12]: r_found = { 1'b1, ipv4_arp_table_eth[12] };
			ipv4_arp_table_ipv4[13]: r_found = { 1'b1, ipv4_arp_table_eth[13] };
			ipv4_arp_table_ipv4[14]: r_found = { 1'b1, ipv4_arp_table_eth[14] };
			ipv4_arp_table_ipv4[15]: r_found = { 1'b1, ipv4_arp_table_eth[15] };
			ipv4_arp_table_ipv4[16]: r_found = { 1'b1, ipv4_arp_table_eth[16] };
			ipv4_arp_table_ipv4[17]: r_found = { 1'b1, ipv4_arp_table_eth[17] };
			ipv4_arp_table_ipv4[18]: r_found = { 1'b1, ipv4_arp_table_eth[18] };
			ipv4_arp_table_ipv4[19]: r_found = { 1'b1, ipv4_arp_table_eth[19] };
			ipv4_arp_table_ipv4[20]: r_found = { 1'b1, ipv4_arp_table_eth[20] };
			ipv4_arp_table_ipv4[21]: r_found = { 1'b1, ipv4_arp_table_eth[21] };
			ipv4_arp_table_ipv4[22]: r_found = { 1'b1, ipv4_arp_table_eth[22] };
			ipv4_arp_table_ipv4[23]: r_found = { 1'b1, ipv4_arp_table_eth[23] };
			ipv4_arp_table_ipv4[24]: r_found = { 1'b1, ipv4_arp_table_eth[24] };
			ipv4_arp_table_ipv4[25]: r_found = { 1'b1, ipv4_arp_table_eth[25] };
			ipv4_arp_table_ipv4[26]: r_found = { 1'b1, ipv4_arp_table_eth[26] };
			ipv4_arp_table_ipv4[27]: r_found = { 1'b1, ipv4_arp_table_eth[27] };
			ipv4_arp_table_ipv4[28]: r_found = { 1'b1, ipv4_arp_table_eth[28] };
			ipv4_arp_table_ipv4[29]: r_found = { 1'b1, ipv4_arp_table_eth[29] };
			ipv4_arp_table_ipv4[30]: r_found = { 1'b1, ipv4_arp_table_eth[30] };
			ipv4_arp_table_ipv4[31]: r_found = { 1'b1, ipv4_arp_table_eth[31] };
			default: r_found = { (1+MAC_WIDTH){1'b0} };
			endcase
		end
	end
`endif

	// ---------------------------------------------------------------------
	// Clocked work:
	always @(posedge clk) begin

		if (reset) begin
			r_ipv4_arp_lut_ipv4_eth_addr <= 48'h000000000000;
			r_ipv4_arp_lut_ipv4_eth_addr_found <= 0;
			r_ipv4_daddr <= 0;
			r_ipv4_arp_lut_out_wr_en <= 0;
		end else begin
			if (i_ipv4_arp_lut_ipv4_daddr_valid) begin
				r_ipv4_arp_lut_ipv4_eth_addr <= 48'h000000000000;
				r_ipv4_arp_lut_ipv4_eth_addr_found <= 0;
				r_ipv4_daddr <= i_ipv4_arp_lut_ipv4_daddr;
				r_ipv4_arp_lut_out_wr_en <= 0;
			end else if (i_ipv4_arp_lut_fib_daddr_valid) begin
`ifdef FIB_LOOKUP_FOR_LOOPS
				casex (w_found)
				4'bxxx1: begin
					r_ipv4_arp_lut_ipv4_eth_addr_found <= 1;
					r_ipv4_arp_lut_ipv4_eth_addr <= r_eaddr_s1;
				end
				4'bxx1x: begin
					r_ipv4_arp_lut_ipv4_eth_addr_found <= 1;
					r_ipv4_arp_lut_ipv4_eth_addr <= r_eaddr_s2;
				end
				4'bx1xx: begin
					r_ipv4_arp_lut_ipv4_eth_addr_found <= 1;
					r_ipv4_arp_lut_ipv4_eth_addr <= r_eaddr_s3;
				end
				4'b1xxx: begin
					r_ipv4_arp_lut_ipv4_eth_addr_found <= 1;
					r_ipv4_arp_lut_ipv4_eth_addr <= r_eaddr_s4;
				end
				default: begin
					r_ipv4_arp_lut_ipv4_eth_addr_found <= 0;
					r_ipv4_arp_lut_ipv4_eth_addr <= 48'h000000000000;
				end
				endcase
				r_ipv4_daddr <= 0;
`else
				r_ipv4_arp_lut_ipv4_eth_addr_found <= r_found[48];
				r_ipv4_arp_lut_ipv4_eth_addr <= r_found[0+:MAC_WIDTH];
`endif
				r_ipv4_arp_lut_out_wr_en <= 1;
			end else begin
				r_ipv4_arp_lut_ipv4_eth_addr <= 48'h000000000000;
				r_ipv4_arp_lut_ipv4_eth_addr_found <= 0;
				r_ipv4_daddr <= 0;
				r_ipv4_arp_lut_out_wr_en <= 0;
			end
		end
	end

// -----------------------------------------------------------------------------

endmodule // ipv4_arp_lut
