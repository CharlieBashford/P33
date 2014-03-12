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
		input				i_is_ipv4,

		// Output signals:
		// Do we want to handle the packet or are there IP optons?
		// Is checksum ok?  Is TTL ok to forward?
		// Destination IP for local IP and lpm lookups.
		output reg			o_can_handle_ipv4,
		output reg			o_ipv4_csum_ok,
		output reg			o_ipv4_ttl_ok,
		output reg [31:0]		o_dst_ipv4
	);

	// ---------------------------------------------------------------------
	// Definitions 
	localparam				TTL_OK_DELAY	= 2'b01;
	localparam				TTL_OK_PASS_ON	= 2'b10;

	// Birds on wires..

	// Local register(s) to keep track of ...
	reg [23:0]				ipv4_csum, ipv4_csum_next;
	reg [31:0]				ipv4_daddr, ipv4_daddr_next;
	reg					r_ttl_ok, r_ttl_ok_next;
	reg [1:0]				state, state_next;
	reg					o_ipv4_ttl_ok_next;
	reg [31:0]				o_dst_ipv4_next;

	// Spaghetti.

	// ---------------------------------------------------------------------
	// Checksum ok?
	always @(*) begin
		// Make sure we always initialise to a (default) value.
		ipv4_csum_next			=	ipv4_csum;
		ipv4_daddr_next			=	ipv4_daddr;
		o_can_handle_ipv4		=	1;
		o_ipv4_csum_ok			=	0;
		o_dst_ipv4_next			=	o_dst_ipv4;

		if (i_is_ipv4 && i_pkt_word1) begin
			o_dst_ipv4_next = 0;

			// Check that there are no IP options used.
			if (i_tdata[143:136] == {8'h45}) begin
				ipv4_csum_next =
					i_tdata[143:128] +
					i_tdata[127:112] +
					i_tdata[111:96] +
					i_tdata[95:80] +
					i_tdata[63:48] +
					i_tdata[47:32] +
					i_tdata[31:16] +
					i_tdata[15:0];
				ipv4_daddr_next[31:16] = i_tdata[15:0];
				ipv4_daddr_next[15:0] = {16'h0000};
			end else begin
				// IP options present or not IPv4.
				// Either way we do not care but it goes to CPU.
				o_can_handle_ipv4 = 0;
				ipv4_daddr_next = 0;
			end
		end else if (i_is_ipv4 && i_pkt_word2) begin
			// Add second half of dst IP.
			ipv4_daddr_next[15:0] = i_tdata[255:240];

			// Finish csum calculations.
			ipv4_csum_next = ipv4_csum_next + i_tdata[255:240];
			// Add carry.
			ipv4_csum_next = ipv4_csum_next[15:0] +
				ipv4_csum_next[23:16];
			// Mask and complement.
			ipv4_csum_next = ipv4_csum_next & 16'hffff;
			ipv4_csum_next = ipv4_csum_next ^ 16'hffff;

			if (ipv4_csum_next[15:0] == 16'h0000) begin
				o_ipv4_csum_ok = 1;
				o_dst_ipv4_next = ipv4_daddr_next;
			end else begin
				o_ipv4_csum_ok = 0;
				o_dst_ipv4_next = 0;
				ipv4_daddr_next = 0;
			end
		end
	end

	// ---------------------------------------------------------------------
	// TTL ok?
	// We must delay the signal by one clock cycle to make it align with
	// the others from ethernet and the IPv4 csum above.
	always @(*) begin
		// Make sure we always initialise to a (default) value.
		state_next			=	state;
		r_ttl_ok_next			=	r_ttl_ok;
		o_ipv4_ttl_ok_next		=	o_ipv4_ttl_ok;

		case (state)
		TTL_OK_DELAY: begin
			r_ttl_ok_next = 0;
			o_ipv4_ttl_ok_next = 0;
			if (i_is_ipv4 && i_pkt_word1) begin
				// Check that the TTL is greater than 0.
				// For a local destination a TTL=1 is ok, for
				// forwarding we would need at least a TTL=2.
				// Pitty we do not yet know the local lookup result.
				if (i_tdata[79:72] > 8'h00)
					r_ttl_ok_next = 1;

				state_next = TTL_OK_PASS_ON;
			end
		end

		TTL_OK_PASS_ON: begin
			if (i_is_ipv4 && i_pkt_word2) begin
				o_ipv4_ttl_ok_next = r_ttl_ok;
				state_next = TTL_OK_DELAY;
			end else begin
				$display("IPV4: WARNING: State out of sync.");
			end
		end

		//default: begin
		//	$display("IPV4: TTL invalid state");
		//	$finish;
		//end
		endcase
	end

	// ---------------------------------------------------------------------
	// Clocked work:
	// reset or advance state machine.
	always @(posedge clk) begin
		if (reset) begin
			ipv4_csum		<=	24'h000000;
			ipv4_daddr		<=	32'h00000000;
			state			<=	TTL_OK_DELAY;
			r_ttl_ok		<=	0;
			o_ipv4_ttl_ok		<=	0;
			o_dst_ipv4		<=	32'h00000000;
		end else begin
			ipv4_csum		<=	ipv4_csum_next;
			ipv4_daddr		<=	ipv4_daddr_next;
			state			<=	state_next;
			r_ttl_ok		<=	r_ttl_ok_next;
			o_ipv4_ttl_ok		<=	o_ipv4_ttl_ok_next;
			o_dst_ipv4		<=	o_dst_ipv4_next;
		end
	end

// -----------------------------------------------------------------------------

endmodule // ipv4
