/*-
 * Copyright (c) 2014, Bjoern A. Zeeb
 * All rights reserved.
 *
 * Ethernet header parsing.
 *
 * Get ethertype, check dmac against our mac on the incoming port or whether
 * it is a broad-/multicast address.
 */
module eth
	// ---------------------------------------------------------------------
	#(
		parameter C_S_AXIS_TDATA_WIDTH=256,
		parameter C_S_AXIS_TUSER_WIDTH=128,
		parameter MAC_WIDTH=48
	)
	// inputs and outputs
	(
		// Always need these; no special prefix.
		input				clk,
		input				reset,

		// Usual signals we need for state machine and data access.
		input [C_S_AXIS_TDATA_WIDTH-1:0] i_tdata,
		input [C_S_AXIS_TUSER_WIDTH-1:0] i_tuser,
		// Singal on whether we are in first word (eth hdr) stage
		input				i_pkt_word1,
		// How do I define these constants (eth addr width) for input?
		input [MAC_WIDTH-1:0]		i_mac0,
		input [MAC_WIDTH-1:0]		i_mac1,
		input [MAC_WIDTH-1:0]		i_mac2,
		input [MAC_WIDTH-1:0]		i_mac3,
		// Trigger reads from state FIFO(s).
		input				i_rd_from_magic,

		// Output signals:
		// Whether the ethernet destination was us, or was a broad-
		// or multi-cast.
		// If ethertype is IPv4.  Do not care much about arp anymore
		// as it is a broad... hmm arp replies are destined to us,
		// *sigh* need to check the ethertype for them as well I guess.
		// But all non-IPv4 goes to CPU.  And in a future we won't have
		// the ARP counter anymore.
		output				o_is_for_us,
		output				o_is_bmcast,
		output				o_is_arp,
		output				o_is_ipv4,
		output				o_eth_out_valid
	);

	// ---------------------------------------------------------------------
	// Definitions 
	localparam				ETHTYPE_IPV4	= 16'h0800;
	localparam				ETHTYPE_ARP	= 16'h0806;
	localparam				BMCAST_BIT	= 248;
	localparam				SRC_PORT_POS	= 16;

	// Local register(s) to keep track of ...
	reg					r_eth_out_wr_en;
	reg					r_is_bmcast;
	reg					r_is_for_us;
	reg					r_is_arp;
	reg					r_is_ipv4;

	// Birds on wires..
	wire [7:0]				w_sport;
	wire [MAC_WIDTH-1:0]			w_dmac;
	wire					w_eth_out_empty;

	// Spaghetti.
	assign					w_sport	=
	    i_tuser[SRC_PORT_POS+7:SRC_PORT_POS];
	assign					w_dmac	= i_tdata[255:208];
	assign					o_eth_out_valid = !w_eth_out_empty;

	// ---------------------------------------------------------------------
	// FIFO.
	fallthrough_small_fifo
	#(
		.WIDTH(4),
		.MAX_DEPTH_BITS(2)
	) eth_out
	// inputs and outputs
	(
		// Inputs
		.clk		(clk),
		.reset		(reset),
		.din		({r_is_bmcast, r_is_for_us, r_is_arp, r_is_ipv4}),	// goes in on 2nd cy
		.rd_en		(i_rd_from_magic),
		.wr_en		(r_eth_out_wr_en),
		// Outputs
		.dout		({o_is_bmcast, o_is_for_us, o_is_arp, o_is_ipv4}),
		.full		(),
		.nearly_full	(),
		.prog_full	(),
		.empty		(w_eth_out_empty)
	);


	// ---------------------------------------------------------------------
	// For us or bmacst?
	// Ethertype?
	// Reset or advance state machine.
	always @(posedge clk) begin
		r_is_bmcast			<= 0;
		r_is_for_us			<= 0;
		r_is_arp			<= 0;
		r_is_ipv4			<= 0;
		r_eth_out_wr_en			<= 0;

		if (reset) begin
			r_eth_out_wr_en		<= 0;

		end else if (i_pkt_word1) begin

			// Ethertype
			case (i_tdata[159:144])
			ETHTYPE_IPV4: begin
				r_is_ipv4 <= 1;
			end

			ETHTYPE_ARP: begin
				r_is_arp <= 1;
			end
			endcase

			// Check if it is a broad-/multi-cast packet.
			if (i_tdata[BMCAST_BIT] == 1'b1) begin
				$display("Broad- or Muticast packet.");
				r_is_bmcast <= 1;
				r_is_for_us <= 1;

			end else begin
				// Validate that the dmac matches the input
				// port.
				// XXX-BZ what about "from CPU"?

				case (w_sport & 8'b01010101)
				// MAC3.
				8'b01000000: begin
					if (w_dmac == i_mac3)
						r_is_for_us <= 1;
					// else garbage, defaults will drop it
				end

				// MAC32
				8'b00010000: begin
					if (w_dmac == i_mac2)
						r_is_for_us <= 1;
					// else garbage, defaults will drop it
				end

				// MAC1.
				8'b00000100: begin
					if (w_dmac == i_mac1)
						r_is_for_us <= 1;
					// else garbage, defaults will drop it
				end

				// MAC0.
				8'b00000001: begin
					if (w_dmac == i_mac0)
						r_is_for_us <= 1;
					// else garbage, defaults will drop it
				end

				default: begin
					// XXX-BZ panic!
					// How to do this in Verilog?
				end
				endcase // w_sport
			end

			r_eth_out_wr_en <= 1;
		end // !reset && !i_pkt_word1
	end

// -----------------------------------------------------------------------------

endmodule // eth
