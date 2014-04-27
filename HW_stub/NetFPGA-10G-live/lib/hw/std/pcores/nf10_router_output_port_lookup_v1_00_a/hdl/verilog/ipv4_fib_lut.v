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
	
		// Trigger reads from state FIFO(s).
		input					i_rd_from_magic,
		// In-HW access for lookups.
		// Destination address to lookup.
		input [31:0]				i_ipv4_fib_lut_daddr,
		input					i_ipv4_fib_lut_daddr_valid,
		// NH found (and with that valid) and NH address.
		output 					o_ipv4_fib_lut_nh_found,
		output [31:0]				o_ipv4_fib_lut_nh,
		output [7:0]				o_ipv4_fib_lut_tuser,
		output					o_ipv4_fib_lut_valid,
		// Immediate outputs for ipv4_arp_lut.
		output reg [31:0]			o_im_ipv4_fib_lut_nh,
		output reg				o_im_ipv4_fib_lut_valid
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

	integer					i;

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
				ipv4_fib_table_mask[i] <= {(1*32){1'b1}};
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
	// Do our table lookup without considering that it might be updated
	// for the moment.

	// ---------------------------------------------------------------------
	reg					r_found_s1, r_found_s2;
	reg					r_found_s3, r_found_s4;
	reg [31:0]				r_nh_s1, r_nh_s2;
	reg [31:0]				r_nh_s3, r_nh_s4;
	reg [7:0]				r_tuser_s1, r_tuser_s2;
	reg [7:0]				r_tuser_s3, r_tuser_s4;
	reg [31:0]				r_tnet_s1, r_dnet_s1;
	reg [31:0]				r_tnet_s2, r_dnet_s2;
	reg [31:0]				r_tnet_s3, r_dnet_s3;
	reg [31:0]				r_tnet_s4, r_dnet_s4;
	reg					r_ipv4_fib_lut_out_wr_en;
	reg					r_ipv4_fib_lut_nh_found;
	reg [31:0]				r_ipv4_fib_lut_nh;
	reg [7:0]				r_ipv4_fib_lut_tuser;

	integer					j, k, l, m;

	// Birds on the wire.
	wire [31:0]				w_daddr;
	wire					w_ipv4_fib_lut_out_empty;

	// Spaghetti.
	assign					w_daddr = i_ipv4_fib_lut_daddr;
	assign					o_ipv4_fib_lut_valid = !w_ipv4_fib_lut_out_empty;

	// ---------------------------------------------------------------------
	// FIFO.
	fallthrough_small_fifo
	#(
		.WIDTH(1 + 32 + 8),
		.MAX_DEPTH_BITS(2)
	) ipv4_local_lut_out
	// inputs and outputs
	(
		// Inputs
		.clk		(clk),
		.reset		(reset),
		.din		({r_ipv4_fib_lut_nh_found, r_ipv4_fib_lut_nh, r_ipv4_fib_lut_tuser}),
		.rd_en		(i_rd_from_magic),
		.wr_en		(r_ipv4_fib_lut_out_wr_en),
		// Outputs
		.dout		({o_ipv4_fib_lut_nh_found, o_ipv4_fib_lut_nh, o_ipv4_fib_lut_tuser}),
		.full		(),
		.nearly_full	(),
		.prog_full	(),
		.empty		(w_ipv4_fib_lut_out_empty)
	);


	// ---------------------------------------------------------------------
	// Do the table lookup in parallellellell.
	always @(
		w_daddr, i_ipv4_fib_lut_daddr, i_ipv4_fib_lut_daddr_valid,
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

		if (i_ipv4_fib_lut_daddr_valid) begin
			r_nh_s1 = 32'h00000000;
			r_tuser_s1 = 8'h00;
			for (j = 0; j < 8; j = j + 1) begin
				if (!r_found_s1) begin
					r_tnet_s1 = ipv4_fib_table_net[j] & ipv4_fib_table_mask[j];
					r_dnet_s1 = w_daddr & ipv4_fib_table_mask[j];
					if (r_tnet_s1 == r_dnet_s1) begin
						r_found_s1 = 1;
						r_nh_s1 = ipv4_fib_table_nh[j];
						r_tuser_s1 = ipv4_fib_table_oif[j];
					end
				end
			end
		end
	end

	always @(
		w_daddr, i_ipv4_fib_lut_daddr, i_ipv4_fib_lut_daddr_valid,
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

		if (i_ipv4_fib_lut_daddr_valid) begin
			r_nh_s2 = 32'h00000000;
			r_tuser_s2 = 8'h00;
			for (k = 8; k < 16; k = k + 1) begin
				if (!r_found_s2) begin
					r_tnet_s2 = ipv4_fib_table_net[k] & ipv4_fib_table_mask[k];
					r_dnet_s2 = w_daddr & ipv4_fib_table_mask[k];
					if (r_tnet_s2 == r_dnet_s2) begin
						r_found_s2 = 1;
						r_nh_s2 = ipv4_fib_table_nh[k];
						r_tuser_s2 = ipv4_fib_table_oif[k];
					end
				end
			end
		end
	end


	always @(
		w_daddr, i_ipv4_fib_lut_daddr, i_ipv4_fib_lut_daddr_valid,
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

		if (i_ipv4_fib_lut_daddr_valid) begin
			r_nh_s3 = 32'h00000000;
			r_tuser_s3 = 8'h00;
			for (l = 16; l < 24; l = l + 1) begin
				if (!r_found_s3) begin
					r_tnet_s3 = ipv4_fib_table_net[l] & ipv4_fib_table_mask[l];
					r_dnet_s3 = w_daddr & ipv4_fib_table_mask[l];
					if (r_tnet_s3 == r_dnet_s3) begin
						r_found_s3 = 1;
						r_nh_s3 = ipv4_fib_table_nh[l];
						r_tuser_s3 = ipv4_fib_table_oif[l];
					end
				end
			end
		end
	end


	always @(
		w_daddr, i_ipv4_fib_lut_daddr, i_ipv4_fib_lut_daddr_valid,
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

		if (i_ipv4_fib_lut_daddr_valid) begin
			r_nh_s4 = 32'h00000000;
			r_tuser_s4 = 8'h00;
			for (m = 24; m < 32; m = m + 1) begin
				if (!r_found_s4) begin
					r_tnet_s4 = ipv4_fib_table_net[m] & ipv4_fib_table_mask[m];
					r_dnet_s4 = w_daddr & ipv4_fib_table_mask[m];
					if (r_tnet_s4 == r_dnet_s4) begin
						r_found_s4 = 1;
						r_nh_s4 = ipv4_fib_table_nh[m];
						r_tuser_s4 = ipv4_fib_table_oif[m];
					end
				end
			end
		end
	end


	// ---------------------------------------------------------------------
	// Clocked work:
	always @(posedge clk) begin

		if (reset) begin
			r_ipv4_fib_lut_nh_found = 0;
			r_ipv4_fib_lut_nh = 32'h00000000;
			r_ipv4_fib_lut_tuser = 8'h00;
			r_ipv4_fib_lut_out_wr_en = 0;
			o_im_ipv4_fib_lut_nh = 32'h00000000;
			o_im_ipv4_fib_lut_valid = 0;

		end else begin
			if (i_ipv4_fib_lut_daddr_valid) begin
				r_ipv4_fib_lut_nh_found =
					(r_found_s1 | r_found_s2 |
					r_found_s3 | r_found_s4);
				r_ipv4_fib_lut_nh =
					(r_found_s1) ? r_nh_s1 :
					(r_found_s2) ? r_nh_s2 :
					(r_found_s3) ? r_nh_s3 :
					(r_found_s4) ? r_nh_s4 :
					32'h00000000;
				if ((r_found_s1 | r_found_s2 | r_found_s3 | r_found_s4) &&
				    r_ipv4_fib_lut_nh == 32'h00000000) begin
					r_ipv4_fib_lut_nh = i_ipv4_fib_lut_daddr;
				end
				r_ipv4_fib_lut_tuser =
					(r_found_s1) ? r_tuser_s1 :
					(r_found_s2) ? r_tuser_s2 :
					(r_found_s3) ? r_tuser_s3 :
					(r_found_s4) ? r_tuser_s4 :
					8'h00;
				r_ipv4_fib_lut_out_wr_en = 1;
				o_im_ipv4_fib_lut_nh = r_ipv4_fib_lut_nh;
				o_im_ipv4_fib_lut_valid = 1;
			end else begin
				r_ipv4_fib_lut_nh_found = 0;
				r_ipv4_fib_lut_nh = 32'h00000000;
				r_ipv4_fib_lut_tuser = 8'h00;
				r_ipv4_fib_lut_out_wr_en = 0;
				o_im_ipv4_fib_lut_nh = 32'h00000000;
				o_im_ipv4_fib_lut_valid = 0;
			end
		end
	end

// -----------------------------------------------------------------------------

endmodule // ipv4_fib_lut
