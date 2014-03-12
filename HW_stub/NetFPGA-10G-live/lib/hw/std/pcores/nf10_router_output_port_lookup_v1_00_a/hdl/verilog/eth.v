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
		input [48-1:0]			i_mac0,
		input [MAC_WIDTH-1:0]		i_mac1,
		input [MAC_WIDTH-1:0]		i_mac2,
		input [MAC_WIDTH-1:0]		i_mac3,


		// Output signals:
		// Whether the ethernet destination was us, or was a broad-
		// or multi-cast.
		// If ethertype is IPv4.  Do not care much about arp anymore
		// as it is a broad... hmm arp replies are destined to us,
		// *sigh* need to check the ethertype for them as well I guess.
		// But all non-IPv4 goes to CPU.  And in a future we won't have
		// the ARP counter anymore.
		output reg			o_is_for_us,
		output reg			o_is_bmcast,
		output reg			o_is_arp,
		output reg			o_is_ipv4,
		output				o_is_valid
	);

	// ---------------------------------------------------------------------
	// Definitions 
	localparam				ETHTYPE_IPV4	= 16'h0800;
	localparam				ETHTYPE_ARP	= 16'h0806;
	localparam				BMCAST_BIT	= 248;
	localparam				SRC_PORT_POS	= 16;

	// Birds on wires..
	wire [7:0]				w_sport;
	wire [MAC_WIDTH-1:0]			w_dmac;

	// Local register(s) to keep track of ...
	//reg [2:0]				state, next_state;
	reg [15:0]				r_ethertype;
	reg					r_valid_1, r_valid_2;

	// Spaghetti.
	assign					w_sport	=
		i_tuser[SRC_PORT_POS+7:SRC_PORT_POS];
	assign					w_dmac	=
		i_tdata[255:208];
	assign					w_etherype =
		i_tdata[159:144];
	assign					o_is_valid =
		r_valid_1 && r_valid_2;

	// ---------------------------------------------------------------------
	// For us or bmacst?
	// Ethertype?
	always @(posedge clk) begin

		if (reset) begin
			o_is_bmcast = 0;
			o_is_for_us = 0;
			r_valid_1 = 0;

		end else if (i_pkt_word1) begin
			o_is_bmcast = 0;
			o_is_for_us = 0;
			r_valid_1 = 0;

			// Check if it is a broad-/multi-cast packet.
			if (i_tdata[BMCAST_BIT] == 1'b1) begin
				$display("Broad- or Muticast packet.");
				o_is_bmcast = 1;
				o_is_for_us = 1;

			end else begin
				o_is_bmcast = 0;

				// Validate that the dmac matches the input
				// port.
				// XXX-BZ what about "from CPU"?

				case (w_sport & 8'b01010101)
				// MAC3.
				8'b01000000: begin
					if (w_dmac == i_mac3)
						o_is_for_us = 1;
					// else garbage, defaults will drop it
				end

				// MAC32
				8'b00010000: begin
					if (w_dmac == i_mac2)
						o_is_for_us = 1;
					// else garbage, defaults will drop it
				end

				// MAC1.
				8'b00000100: begin
					if (w_dmac == i_mac1)
						o_is_for_us = 1;
					// else garbage, defaults will drop it
				end

				// MAC0.
				8'b00000001: begin
					if (w_dmac == i_mac0)
						o_is_for_us = 1;
					// else garbage, defaults will drop it
				end

				default: begin
					// XXX-BZ panic!
					// How to do this in Verilog?
				end
				endcase // w_sport
			end
			if (o_is_for_us || o_is_bmcast) begin
				r_valid_1 = 1;
			end
		end
	end

	// ---------------------------------------------------------------------
	// Clocked work:
	// reset or advance state machine.
	always @(posedge clk) begin
		if (reset) begin
			r_ethertype <= 0;
			o_is_arp <= 0;
			o_is_ipv4 <= 0;
			r_valid_2 <= 0;

		end else begin
			if (i_pkt_word1) begin
				r_valid_2 <= 0;

				// Extract the ethertype.
				r_ethertype <= i_tdata[159:144];
				case (r_ethertype)
				ETHTYPE_ARP: begin
					o_is_arp <= 1;
					o_is_ipv4 <= 0;
				end

				ETHTYPE_IPV4: begin
					o_is_arp <= 0;
					o_is_ipv4 <= 1;
				end

				default: begin
					o_is_arp <= 0;
					o_is_ipv4 <= 0;
				end
				endcase

				r_valid_2 <= 1;
			end
		end
	end

// -----------------------------------------------------------------------------

endmodule // eth
