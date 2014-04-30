/*-
 * Copyright (c) 2014, Bjoern A. Zeeb
 * All rights reserved.
 *
 * IPv4 layer handling.
 *
 * Do checksum and TTL check.  Extract destination IP for later lookups.
 */
module ipv4
	// ---------------------------------------------------------------------
	#(
		parameter C_S_AXIS_TDATA_WIDTH=256
	)
	// inputs and outputs
	(
		// Always need these; no special prefix.
		input				clk,
		input				reset,

		// Usual signals we need for state machine and data access.
		input [C_S_AXIS_TDATA_WIDTH-1:0] i_tdata,
		// Singal on whether we are in first word (eth hdr) or
		// 2nd word (last half of dst IP) stage.
		input				i_pkt_word1,
		input				i_pkt_word2,

		// Trigger reads from state FIFO(s).
		input				i_rd_from_magic,

		// Output signals:
		// Do we want to handle the packet or are there IP optons?
		// Is checksum ok?  Is TTL ok to forward?
		// Destination IP for local IP and lpm lookups.
		// IPv4 data 2cy.
		output				o_can_handle_ipv4,
		output				o_ipv4_ttl_ok,
`ifdef NOT_DISABLE_UNSUED
		output [31:0]			o_ipv4_daddr,
`endif
		output				o_ipv4_out_valid,
		// Csum 3cy.
		output				o_ipv4_csum_ok,
		output [15:0]			o_ipv4_csum_updated,
		output				o_ipv4_csum_out_valid,
		// Immediate outputs for ipv4_{local,fib}_lut.
		output reg [31:0]		o_im_ipv4_daddr,
		output reg			o_im_ipv4_daddr_valid
	);

	// ---------------------------------------------------------------------
	// Definitions 
	localparam			TTL_OK_DELAY	= 1'b1;
	localparam			TTL_OK_PASS_ON	= 1'b0;

	// Local register(s) to keep track of ...
	// CSUM
	reg [17:0]			r_h1_ipv4_csum, r_h1_ipv4_csum_next;
	reg [17:0]			r_h2_ipv4_csum, r_h2_ipv4_csum_next;
	reg [19:0]			r_ipv4_csum;
	reg [15:0]			r_ipv4_csum_r;
	reg [31:0]			r_ipv4_daddr;
	reg				r_is_ipv4_noopt, r_is_ipv4_noopt_next;
	reg				r_ipv4_csum_ok;
	reg				r_cy_3, r_cy_3_next;
	reg [15:0]			r_ocsum, r_ocsum_next;
	reg [16:0]			r_ipv4_csum_updated;
	reg [15:0]			r_ipv4_csum_updated_folded;
	// TTL
	reg 				r_state, r_state_next;
	reg				r_ttl_ok, r_ttl_ok_next;
	// FIFOs.
	reg				r_ipv4_out_wr_en;
	reg				r_ipv4_out_wr_en_next;
	reg				r_ipv4_csum_out_wr_en;

	// Birds on wires..
	wire				w_is_ipv4_noopt;
	wire [18:0]			w_h_ipv4_csum;
	wire [16:0]			w_h1_1, w_h1_2;
	wire [16:0]			w_h2_1, w_h2_2;
	wire				w_ipv4_out_empty;
	wire				w_ipv4_csum_out_empty;

	// Spaghetti.
	assign w_is_ipv4_noopt		= (i_tdata[143:136] == {8'h45}) ? 1 : 0;
	assign w_h1_1			= i_tdata[128+:16] + i_tdata[112+:16];
	assign w_h1_2			= i_tdata[96+:16] + i_tdata[80+:16];
	assign w_h2_1			= i_tdata[64+:16] + i_tdata[48+:16];
	assign w_h2_2			= i_tdata[32+:16] + i_tdata[16+:16];
	assign w_h_ipv4_csum		= r_h1_ipv4_csum[17:0] + r_h2_ipv4_csum[17:0];
	assign o_ipv4_out_valid		= !w_ipv4_out_empty;
	assign o_ipv4_csum_out_valid	= !w_ipv4_csum_out_empty;

	// ---------------------------------------------------------------------
	// FIFOs.
	fallthrough_small_fifo
	#(
`ifdef NOT_DISABLE_UNSUED
		.WIDTH(1 + 1 + 32),
`else
		.WIDTH(1 + 1),
`endif
		.MAX_DEPTH_BITS(2)
	) ipv4_out
	// inputs and outputs
	(
		// Inputs
		.clk		(clk),
		.reset		(reset),
`ifdef NOT_DISABLE_UNSUED
		.din		({r_ttl_ok, r_is_ipv4_noopt, r_ipv4_daddr}), // goes in on 2nd cy
`else
		.din		({r_ttl_ok, r_is_ipv4_noopt}),		 // goes in on 2nd cy
`endif
		.rd_en		(i_rd_from_magic),
		.wr_en		(r_ipv4_out_wr_en),
		// Outputs
`ifdef NOT_DISABLE_UNSUED
		.dout		({o_ipv4_ttl_ok, o_can_handle_ipv4, o_ipv4_daddr}),
`else
		.dout		({o_ipv4_ttl_ok, o_can_handle_ipv4}),
`endif
		.full		(),
		.nearly_full	(),
		.prog_full	(),
		.empty		(w_ipv4_out_empty)
	);

	fallthrough_small_fifo
	#(
		.WIDTH(1 + 16),
		.MAX_DEPTH_BITS(2)
	) ipv4_csum_out
	// inputs and outputs
	(
		// Inputs
		.clk		(clk),
		.reset		(reset),
		.din		({r_ipv4_csum_ok, r_ipv4_csum_updated_folded}),	// goes in on 3rd cy
		.rd_en		(i_rd_from_magic),
		.wr_en		(r_ipv4_csum_out_wr_en),
		// Outputs
		.dout		({o_ipv4_csum_ok, o_ipv4_csum_updated}),
		.full		(),
		.nearly_full	(),
		.prog_full	(),
		.empty		(w_ipv4_csum_out_empty)
	);

	// ---------------------------------------------------------------------
	// Checksum ok?
	// We split this over 3 clock cycles;  the first two go along pktstate
	// the 3rd one leaks into the lookup stage but also updates it based on
	// the assumption that we decrement the TTL by 1 for forwarding and then
	// provided the result to last stage packet assembly.

	// 3rd cycle stage.
	always @(
		r_cy_3, r_ipv4_csum, r_ocsum
	) begin
		// Make sure we always initialise to a (default) value.
		r_ipv4_csum_ok		= 0;
		r_ipv4_csum_out_wr_en	= 0;
		r_ipv4_csum_r		= 0;
		r_ipv4_csum_updated	= 0;
		r_ipv4_csum_updated_folded = 0;

		if (r_cy_3) begin
			// Add carry.
			r_ipv4_csum_r = r_ipv4_csum[15:0] + r_ipv4_csum[18:16];

			// (Mask and) complement.
			// Do not mask or complement.  We can just check
			// the right bits and against ffff instead of 0000.
			//r_ipv4_csum_r = r_ipv4_csum_r & 16'hffff;
			//r_ipv4_csum_r = r_ipv4_csum_r ^ 16'hffff;

			//if (r_ipv4_csum_r[15:0] == 16'h0000) begin
			//if (r_ipv4_csum_r[15:0] == 16'hffff) begin
			r_ipv4_csum_ok = &r_ipv4_csum_r[15:0];

			// We did not complement, so add one rather than
			// subtracting one.  If we hit a carry, that is
			// too bad. grml.

			r_ipv4_csum_updated = r_ocsum[15:0] + 16'h0100;	// NBO, byte swapped
			r_ipv4_csum_updated_folded = r_ipv4_csum_updated[15:0] +
			    r_ipv4_csum_updated[16];

			r_ipv4_csum_out_wr_en = 1;
		end
	end

	// ---------------------------------------------------------------------
	// Checksum TDATA, IPv4, Options.
	always @(
		w_is_ipv4_noopt, r_is_ipv4_noopt, r_ocsum,
		r_h1_ipv4_csum, r_h2_ipv4_csum,
		i_pkt_word1, i_pkt_word2,
		i_tdata[63:48], i_tdata[15:0], i_tdata[255:240],
		w_h1_1, w_h1_2, w_h2_1, w_h2_2, w_h_ipv4_csum
	) begin
		// Make sure we always initialise to a (default) value.
		r_is_ipv4_noopt_next	= r_is_ipv4_noopt;
		r_ocsum_next		= r_ocsum;
		r_h1_ipv4_csum_next	= r_h1_ipv4_csum;
		r_h2_ipv4_csum_next	= r_h2_ipv4_csum;
		r_cy_3_next		= 0;

		if (i_pkt_word1) begin
			// IPv4, no options?
			r_is_ipv4_noopt_next = w_is_ipv4_noopt;

			// Save original checksum.
			r_ocsum_next = i_tdata[48+:16];

			// Checksum calculations.
			r_h1_ipv4_csum_next = w_h1_1 + w_h1_2;
			r_h2_ipv4_csum_next = i_tdata[0+:16] + w_h2_1 + w_h2_2;

		end else if (i_pkt_word2) begin
			// Finish checksum calculations.
			r_ipv4_csum = i_tdata[255:240] + w_h_ipv4_csum;

			// Carry checksum calculations on beyond i_pkt_word[12].
			r_cy_3_next = 1;
		end
	end

	// ---------------------------------------------------------------------
	// IPv4 Destination address extraction.
	always @(
		i_pkt_word1, i_pkt_word2,
		i_tdata[15:0], i_tdata[255:240],
		r_ipv4_daddr
	) begin
		// Make sure we always initialise to a (default) value.
		o_im_ipv4_daddr	= r_ipv4_daddr;
		o_im_ipv4_daddr_valid	= 0;

		if (i_pkt_word1) begin
			o_im_ipv4_daddr[31:16] = i_tdata[15:0];

		end else if (i_pkt_word2) begin
			// Add second half of dst IP.
			o_im_ipv4_daddr[15:0] = i_tdata[255:240];
			o_im_ipv4_daddr_valid	= 1;
		end
	end

	// ---------------------------------------------------------------------
	// TTL ok?
	// We must delay the signal by one clock cycle to make it align with
	// the others from ethernet and the IPv4 csum above.
	always @(
		i_tdata[79:72], i_pkt_word1, i_pkt_word2, r_state, r_ttl_ok
	) begin
		// Make sure we always initialise to a (default) value.
		r_state_next			= r_state;
		r_ttl_ok_next			= r_ttl_ok;
		r_ipv4_out_wr_en_next		= 0;

		case (r_state)
		TTL_OK_DELAY: begin
			r_ttl_ok_next = 0;
			if (i_pkt_word1) begin
				// Check that the TTL is greater than 0.
				// For a local destination a TTL=1 is ok, for
				// forwarding we would need at least a TTL=2.
				// Pitty we do not yet know the local lookup result.
				// The magic module has to do that check.
				if (i_tdata[79:72] > 8'h00)
					r_ttl_ok_next = 1;

				r_state_next = TTL_OK_PASS_ON;
			end
		end

		TTL_OK_PASS_ON: begin
			if (i_pkt_word2) begin
				r_ipv4_out_wr_en_next = 1;
				r_state_next = TTL_OK_DELAY;
			end
		end
		endcase
	end

	// ---------------------------------------------------------------------
	// Clocked work:
	// reset or advance state machine.
	always @(posedge clk) begin
		if (reset) begin
			r_ipv4_out_wr_en	<=	0;
			// Checksum, IPv4 Options, Cycle 3
			r_is_ipv4_noopt		<=	0;
			r_ocsum			<=	0;
			r_h1_ipv4_csum		<=	{18{1'b0}};
			r_h2_ipv4_csum		<=	{18{1'b0}};
			r_cy_3			<=	0;
			// Daddr
			r_ipv4_daddr		<=	32'h00000000;
			// TTL
			r_state			<=	TTL_OK_DELAY;
			r_ttl_ok		<=	0;
		end else begin
			r_ipv4_out_wr_en	<=	r_ipv4_out_wr_en_next;
			// Checksum, IPv4 Options, Cycle 3
			r_is_ipv4_noopt		<=	r_is_ipv4_noopt_next;
			r_ocsum			<=	r_ocsum_next;
			r_h1_ipv4_csum		<=	r_h1_ipv4_csum_next;
			r_h2_ipv4_csum		<=	r_h2_ipv4_csum_next;
			r_cy_3			<=	r_cy_3_next;
			// Daddr
			r_ipv4_daddr		<=	o_im_ipv4_daddr;
			// TTL
			r_state			<=	r_state_next;
			r_ttl_ok		<=	r_ttl_ok_next;
		end
	end

// -----------------------------------------------------------------------------

endmodule // ipv4
