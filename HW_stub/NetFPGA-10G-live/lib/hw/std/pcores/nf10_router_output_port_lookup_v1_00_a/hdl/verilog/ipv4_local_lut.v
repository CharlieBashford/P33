/*-
 * Copyright (c) 2014, Bjoern A. Zeeb
 * All rights reserved.
 *
 * IPv4 local address lookup table.
 *
 * Determine if a destination IPv4 address is local.
 * Provide the interface to user space for updating the table.
 */
module ipv4_local_lut
	// ---------------------------------------------------------------------
	#(
		parameter IPV4_LOCAL_LUT_ROWS=3,
		parameter IPV4_LOCAL_LUT_ROW_BITS=5
	)
	// inputs and outputs
	(
		// Always need these; no special prefix.
		input					Bus2IP_Clk,
		input					Bus2IP_Reset,

		// Table input and output.
		// (Keep ordering as in ipif_table_regs.)
		input					i_ipv4_local_lut_rd_req,
		output reg				o_ipv4_local_lut_rd_ack,
		input [IPV4_LOCAL_LUT_ROW_BITS-1:0]	i_ipv4_local_lut_rd_addr,
		output [31:0]				o_ipv4_local_lut_rd_ipv4_addr,
		input					i_ipv4_local_lut_wr_req,
		output reg				o_ipv4_local_lut_wr_ack,
		input [IPV4_LOCAL_LUT_ROW_BITS-1:0]	i_ipv4_local_lut_wr_addr,
		input [31:0]				i_ipv4_local_lut_wr_ipv4_addr,

		// Always need these; no special prefix.
		input					clk,
		input					reset,

		// Trigger reads from state FIFO(s).
		input					i_rd_from_magic,
		// Destination address to lookup.
		input [31:0]				i_ipv4_local_lut_ipv4_daddr,
		input					i_ipv4_local_lut_ipv4_daddr_valid,
		// Is the address local?
		output					o_ipv4_local_lut_ipv4_daddr_is_local,
		output					o_ipv4_local_lut_ipv4_daddr_is_local_valid
	);

	// ---------------------------------------------------------------------
	// Definitions 
	//localparam	...			= ..;

	// Birds on wires..
	//wire	...				w_...;

	// Local register(s) to keep track of ...
	// 32 IPv4 address entries (32 bit each)
	reg[31:0]		ipv4_local_addr_table [0:IPV4_LOCAL_LUT_ROWS-1];
	reg[IPV4_LOCAL_LUT_ROW_BITS-1:0]	row_num_select;

	integer					i;

	// Spaghetti.
	assign o_ipv4_local_lut_rd_ipv4_addr	=
		ipv4_local_addr_table[row_num_select];
	//assign o_ipv4_local_lut_rd_ack		= i_ipv4_local_lut_rd_req;
	//assign o_ipv4_local_lut_wr_ack		= i_ipv4_local_lut_wr_req;

	// ---------------------------------------------------------------------
	// Clocked work:
	// reset table or handle table reads and writes.
	always @(posedge Bus2IP_Clk) begin
		o_ipv4_local_lut_rd_ack <= 0;
		o_ipv4_local_lut_wr_ack <= 0;

		if (Bus2IP_Reset) begin
			for (i = 0; i < 32; i = i + 1)
				ipv4_local_addr_table[i] <= {32{1'b0}};
		end else begin
			if (i_ipv4_local_lut_rd_req) begin
				row_num_select <= i_ipv4_local_lut_rd_addr;
				o_ipv4_local_lut_rd_ack <= 1;
			end else
			if (i_ipv4_local_lut_wr_req) begin
				ipv4_local_addr_table[i_ipv4_local_lut_wr_addr]
					<= i_ipv4_local_lut_wr_ipv4_addr;
				o_ipv4_local_lut_wr_ack <= 1;
			end
		end
	end

	// ---------------------------------------------------------------------
	// Do our table lookup without considering that it might be updated
	// for the moment.

	// ---------------------------------------------------------------------
`ifdef FIB_LOOKUP_FOR_LOOPS
	reg					r_is_local_s1, r_is_local_s2;
	reg					r_is_local_s3, r_is_local_s4;
`else
	reg					r_is_local;
`endif
	reg					r_ipv4_local_lut_ipv4_daddr_is_local;
	reg					r_ipv4_local_lut_out_wr_en;

`ifdef FIB_LOOKUP_FOR_LOOPS
	integer					j, k, l, m;
`endif

	// Birds on the wire.
	wire [31:0]				w_daddr;
	wire					w_ipv4_local_lut_out_empty;

	// Spaghetti.
	assign					w_daddr = i_ipv4_local_lut_ipv4_daddr;
	assign					o_ipv4_local_lut_ipv4_daddr_is_local_valid = !w_ipv4_local_lut_out_empty;

	// ---------------------------------------------------------------------
	// FIFO.
	fallthrough_small_fifo
	#(
		.WIDTH(1),
		.MAX_DEPTH_BITS(2)
	) ipv4_local_lut_out
	// inputs and outputs
	(
		// Inputs
		.clk		(clk),
		.reset		(reset),
		.din		(r_ipv4_local_lut_ipv4_daddr_is_local),
		.rd_en		(i_rd_from_magic),
		.wr_en		(r_ipv4_local_lut_out_wr_en),
		// Outputs
		.dout		(o_ipv4_local_lut_ipv4_daddr_is_local),
		.full		(),
		.nearly_full	(),
		.prog_full	(),
		.empty		(w_ipv4_local_lut_out_empty)
	);


	// ---------------------------------------------------------------------
	// Do the table lookup in parallellellell.
`ifdef FIB_LOOKUP_FOR_LOOPS
	always @(
		w_daddr, i_ipv4_local_lut_ipv4_daddr, i_ipv4_local_lut_ipv4_daddr_valid,
		ipv4_local_addr_table[0], ipv4_local_addr_table[1],
		ipv4_local_addr_table[2], ipv4_local_addr_table[3],
		ipv4_local_addr_table[4], ipv4_local_addr_table[5],
		ipv4_local_addr_table[6], ipv4_local_addr_table[7]
	) begin
		r_is_local_s1 = 0;
		if (i_ipv4_local_lut_ipv4_daddr_valid) begin
			for (j = 0; j < 8; j = j + 1) begin
				if (!r_is_local_s1 &&
				    ipv4_local_addr_table[j] == w_daddr)
				begin
					r_is_local_s1 = 1;
				end
			end
		end
	end

	always @(
		w_daddr, i_ipv4_local_lut_ipv4_daddr, i_ipv4_local_lut_ipv4_daddr_valid,
		ipv4_local_addr_table[8], ipv4_local_addr_table[9],
		ipv4_local_addr_table[10], ipv4_local_addr_table[11],
		ipv4_local_addr_table[12], ipv4_local_addr_table[13],
		ipv4_local_addr_table[14], ipv4_local_addr_table[15]
	) begin
		r_is_local_s2 = 0;
		if (i_ipv4_local_lut_ipv4_daddr_valid) begin
			for (k = 8; k < 16; k = k + 1) begin
				if (!r_is_local_s2 &&
				    ipv4_local_addr_table[k] == w_daddr)
				begin
					r_is_local_s2 = 1;
				end
			end
		end
	end

	always @(
		w_daddr, i_ipv4_local_lut_ipv4_daddr, i_ipv4_local_lut_ipv4_daddr_valid,
		ipv4_local_addr_table[16], ipv4_local_addr_table[17],
		ipv4_local_addr_table[18], ipv4_local_addr_table[19],
		ipv4_local_addr_table[20], ipv4_local_addr_table[21],
		ipv4_local_addr_table[22], ipv4_local_addr_table[23]
	) begin
		r_is_local_s3 = 0;
		if (i_ipv4_local_lut_ipv4_daddr_valid) begin
			for (l = 16; l < 24; l = l + 1) begin
				if (!r_is_local_s3 &&
				    ipv4_local_addr_table[l] == w_daddr)
				begin
					r_is_local_s3 = 1;
				end
			end
		end
	end

	always @(
		w_daddr, i_ipv4_local_lut_ipv4_daddr, i_ipv4_local_lut_ipv4_daddr_valid,
		ipv4_local_addr_table[24], ipv4_local_addr_table[25],
		ipv4_local_addr_table[26], ipv4_local_addr_table[27],
		ipv4_local_addr_table[28], ipv4_local_addr_table[29],
		ipv4_local_addr_table[30], ipv4_local_addr_table[31]
	) begin
		r_is_local_s4 = 0;
		if (i_ipv4_local_lut_ipv4_daddr_valid) begin
			for (m = 24; m < 32; m = m + 1) begin
				if (!r_is_local_s4 &&
				    ipv4_local_addr_table[m] == w_daddr)
				begin
					r_is_local_s4 = 1;
				end
			end
		end
	end
`else
	always @(
		w_daddr, i_ipv4_local_lut_ipv4_daddr, i_ipv4_local_lut_ipv4_daddr_valid,
		ipv4_local_addr_table[0], ipv4_local_addr_table[1],
		ipv4_local_addr_table[2], ipv4_local_addr_table[3],
		ipv4_local_addr_table[4], ipv4_local_addr_table[5],
		ipv4_local_addr_table[6], ipv4_local_addr_table[7],
		ipv4_local_addr_table[8], ipv4_local_addr_table[9],
		ipv4_local_addr_table[10], ipv4_local_addr_table[11],
		ipv4_local_addr_table[12], ipv4_local_addr_table[13],
		ipv4_local_addr_table[14], ipv4_local_addr_table[15],
		ipv4_local_addr_table[16], ipv4_local_addr_table[17],
		ipv4_local_addr_table[18], ipv4_local_addr_table[19],
		ipv4_local_addr_table[20], ipv4_local_addr_table[21],
		ipv4_local_addr_table[22], ipv4_local_addr_table[23],
		ipv4_local_addr_table[24], ipv4_local_addr_table[25],
		ipv4_local_addr_table[26], ipv4_local_addr_table[27],
		ipv4_local_addr_table[28], ipv4_local_addr_table[29],
		ipv4_local_addr_table[30], ipv4_local_addr_table[31]
	) begin
		r_is_local = 0;

		if (i_ipv4_local_lut_ipv4_daddr_valid) begin
			case (w_daddr)
			ipv4_local_addr_table[0]: r_is_local = 1;
			ipv4_local_addr_table[1]: r_is_local = 1;
			ipv4_local_addr_table[2]: r_is_local = 1;
			ipv4_local_addr_table[3]: r_is_local = 1;
			ipv4_local_addr_table[4]: r_is_local = 1;
			ipv4_local_addr_table[5]: r_is_local = 1;
			ipv4_local_addr_table[6]: r_is_local = 1;
			ipv4_local_addr_table[7]: r_is_local = 1;
			ipv4_local_addr_table[8]: r_is_local = 1;
			ipv4_local_addr_table[9]: r_is_local = 1;
			ipv4_local_addr_table[10]: r_is_local = 1;
			ipv4_local_addr_table[11]: r_is_local = 1;
			ipv4_local_addr_table[12]: r_is_local = 1;
			ipv4_local_addr_table[13]: r_is_local = 1;
			ipv4_local_addr_table[14]: r_is_local = 1;
			ipv4_local_addr_table[15]: r_is_local = 1;
			ipv4_local_addr_table[16]: r_is_local = 1;
			ipv4_local_addr_table[17]: r_is_local = 1;
			ipv4_local_addr_table[18]: r_is_local = 1;
			ipv4_local_addr_table[19]: r_is_local = 1;
			ipv4_local_addr_table[20]: r_is_local = 1;
			ipv4_local_addr_table[21]: r_is_local = 1;
			ipv4_local_addr_table[22]: r_is_local = 1;
			ipv4_local_addr_table[23]: r_is_local = 1;
			ipv4_local_addr_table[24]: r_is_local = 1;
			ipv4_local_addr_table[25]: r_is_local = 1;
			ipv4_local_addr_table[26]: r_is_local = 1;
			ipv4_local_addr_table[27]: r_is_local = 1;
			ipv4_local_addr_table[28]: r_is_local = 1;
			ipv4_local_addr_table[29]: r_is_local = 1;
			ipv4_local_addr_table[30]: r_is_local = 1;
			ipv4_local_addr_table[31]: r_is_local = 1;
			default: r_is_local = 0;
			endcase
		end
	end
`endif

	// ---------------------------------------------------------------------
	// Clocked work:
	// Split into two states to (a) make synth more happy and (b) we want
	// the delay anyway.
	always @(posedge clk) begin

		if (reset) begin
			r_ipv4_local_lut_ipv4_daddr_is_local	<= 0;
			r_ipv4_local_lut_out_wr_en		<= 0;

		end else begin
			if (i_ipv4_local_lut_ipv4_daddr_valid) begin
				r_ipv4_local_lut_ipv4_daddr_is_local <=
`ifdef FIB_LOOKUP_FOR_LOOPS
					(r_is_local_s1 | r_is_local_s2 |
					 r_is_local_s3 | r_is_local_s4);
`else
					r_is_local;
`endif
				r_ipv4_local_lut_out_wr_en <= 1;
			end else begin
				r_ipv4_local_lut_out_wr_en <= 0;
				r_ipv4_local_lut_ipv4_daddr_is_local <= 0;
			end
		end
	end

// -----------------------------------------------------------------------------

endmodule // ipv4_local_lut
