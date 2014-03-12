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
		//input [7:0]				i_ipv4_fib_lut_wr_ipv4_oif,
		input [31:0]				i_ipv4_fib_lut_wr_ipv4_oif,
		input [31:0]				i_ipv4_fib_lut_wr_ipv4_nh,
		input [31:0]				i_ipv4_fib_lut_wr_ipv4_mask,
		input [31:0]				i_ipv4_fib_lut_wr_ipv4_net,

		// Always need these; no special prefix.
		input					clk,
		input					reset,

		// In-HW access for lookups.
		// Destination address to lookup.
		input [31:0]				i_ipv4_fib_lut_daddr,
		input					i_ipv4_fib_lut_daddr_valid,
		// NH found (and with that valid) and NH address.
		output reg				o_ipv4_fib_lut_nh_found,
		output reg [31:0]			o_ipv4_fib_lut_nh,
		output reg [7:0]			o_ipv4_fib_lut_tuser
	);

	// ---------------------------------------------------------------------
	// Definitions 
	//localparam	...			= ..;

	// Birds on wires..
	//wire	...				w_...;

	// Local register(s) to keep track of ...
	// 32 { IPv4 net/mask/nh entries (32 bit each), output queue (8 bit?) }
	reg[7:0]		ipv4_fib_table_oif  [0:IPV4_FIB_LUT_ROWS-1];
	reg[31:0]		ipv4_fib_table_nh   [0:IPV4_FIB_LUT_ROWS-1];
	reg[31:0]		ipv4_fib_table_mask [0:IPV4_FIB_LUT_ROWS-1];
	reg[31:0]		ipv4_fib_table_net  [0:IPV4_FIB_LUT_ROWS-1];
	reg[IPV4_FIB_LUT_ROW_BITS-1:0]		row_num_select;

	integer					i, j;

	// Spaghetti.
	assign o_ipv4_fib_lut_rd_ipv4_oif	=
		ipv4_fib_table_oif[row_num_select];
	assign o_ipv4_fib_lut_rd_ipv4_nh	=
		ipv4_fib_table_nh[row_num_select];
	assign o_ipv4_fib_lut_rd_ipv4_mask	=
		ipv4_fib_table_mask[row_num_select];
	assign o_ipv4_fib_lut_rd_ipv4_net	=
		ipv4_fib_table_net[row_num_select];
	//assign o_ipv4_fib_lut_rd_ack		= i_ipv4_fib_lut_rd_req;
	//assign o_ipv4_fib_lut_wr_ack		= i_ipv4_fib_lut_wr_req;

	// ---------------------------------------------------------------------
	// Clocked work:
	// reset table or handle table reads and writes.
	always @(posedge Bus2IP_Clk) begin
		o_ipv4_fib_lut_rd_ack <= 0;
		o_ipv4_fib_lut_wr_ack <= 0;

		if (Bus2IP_Reset) begin
			for (i = 0; i < 32; i = i + 1) begin
				ipv4_fib_table_oif[i]  <= {(1*32){1'b0}};
				ipv4_fib_table_nh[i]   <= {(1*32){1'b0}};
				ipv4_fib_table_mask[i] <= {(1*32){1'b0}};
				ipv4_fib_table_net[i]  <= {(1*32){1'b0}};
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
				ipv4_fib_table_mask[i_ipv4_fib_lut_wr_addr]
					<= i_ipv4_fib_lut_wr_ipv4_mask;
				ipv4_fib_table_net[i_ipv4_fib_lut_wr_addr]
					<= i_ipv4_fib_lut_wr_ipv4_net;
				o_ipv4_fib_lut_wr_ack <= 1;
			end
		end
	end

	// ---------------------------------------------------------------------
	// XXX-BZ table lookup.
	// ---------------------------------------------------------------------
	// Do our table lookup without considering that it might be updated
	// for the moment.

	// ---------------------------------------------------------------------
	localparam				FIRST_STAGE	= 1'b1;
	localparam				SECOND_STAGE	= 1'b0;

	reg 					state, state_next;
	reg [31:0]				r_daddr;
	reg [31:0]				r_tnet, r_dnet;

	// ---------------------------------------------------------------------
	// Clocked work:
	// Split into two states to (a) make synth more happy and (b) we want
	// the delay anyway, well not really for this as two cam lookups
	// would be possible in two clock cycles in the future.
	always @(posedge clk) begin
		state_next				= state;

		if (reset) begin
			o_ipv4_fib_lut_nh_found = 0;
			o_ipv4_fib_lut_nh = 32'h00000000;
			o_ipv4_fib_lut_tuser = 8'h00;
			state = FIRST_STAGE;

		end else begin
			case (state) 
			FIRST_STAGE: begin
				if (i_ipv4_fib_lut_daddr_valid) begin
					o_ipv4_fib_lut_nh_found = 0;
					o_ipv4_fib_lut_nh = 32'h00000000;
					o_ipv4_fib_lut_tuser = 8'h00;
					r_daddr = i_ipv4_fib_lut_daddr;
					for (j = 0; j < 16; j = j + 1) begin
						r_tnet = ipv4_fib_table_net[j] & ipv4_fib_table_mask[j];
						r_dnet = r_daddr & ipv4_fib_table_mask[j];
						if (!o_ipv4_fib_lut_nh_found && (r_tnet == r_dnet))
						begin
							o_ipv4_fib_lut_nh_found = 1;
							o_ipv4_fib_lut_nh = ipv4_fib_table_nh[j];
							o_ipv4_fib_lut_tuser = ipv4_fib_table_oif[j];
						end
					end
					state_next = SECOND_STAGE;	
				end
			end

			SECOND_STAGE: begin
				for (j = 16; j < 32; j = j + 1) begin
					r_tnet = ipv4_fib_table_net[j] & ipv4_fib_table_mask[j];
					r_dnet = r_daddr & ipv4_fib_table_mask[j];
					if (!o_ipv4_fib_lut_nh_found && (r_tnet == r_dnet))
					begin
						o_ipv4_fib_lut_nh_found = 1;
						o_ipv4_fib_lut_nh = ipv4_fib_table_nh[j];
						o_ipv4_fib_lut_tuser = ipv4_fib_table_oif[j];
					end
				end
				state_next = FIRST_STAGE;	
			end

			//default: begin
			//	o_ipv4_fib_lut_nh_found = 0;
			//	o_ipv4_fib_lut_nh = 32'h00000000;
			//	o_ipv4_fib_lut_tuser = 8'h00;
			//end
			endcase
		end

		state = state_next;
	end

// -----------------------------------------------------------------------------

endmodule // ipv4_fib_lut
