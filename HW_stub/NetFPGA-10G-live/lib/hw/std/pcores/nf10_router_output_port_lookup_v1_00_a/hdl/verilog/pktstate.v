/*-
 * Copyright (c) 2014, Bjoern A. Zeeb
 * All rights reserved.
 *
 * Packet state module.
 *
 * This just factors out the state machine where in the packet we are.
 * We are interested in three states, two for parsing headers and and
 * optional one that just lets data passthrough until the end of the packet.
 */
module pktstate
	// ---------------------------------------------------------------------
	#(
		parameter C_S_AXIS_TUSER_WIDTH=128
	)
	// inputs and outputs
	(
		// Always need these; no special prefix.
		input					clk,
		input					reset,

		// Usual signals we need for state machine and data access.
		input [C_S_AXIS_TUSER_WIDTH-1:0]	i_tuser,
		input					i_tvalid,
		input					i_tlast,
		// Trigger reads from state FIFO(s).
		input					i_rd_from_magic,

		// Output signals we need elsewhere to trigger actions on.
		// word1 is the ethernet header and initial IPv4 header.
		// word2 is the second half of the dst ip and options/pad/ulp.
		// Assumption: no VLANs or similar.
		output reg				o_pkt_word1,
		output reg				o_pkt_word2,
		output					o_pkt_is_from_cpu,
		output					o_pktstate_valid
	);

	// ---------------------------------------------------------------------
	// Definitions for the state machine (avoid 0 to ease debugging):
	// PKT_START is the first C_S_AXIS_TDATA_WIDTH of data (word1),
	// PKT_WORD2 is the second C_S_AXIS_TDATA_WIDTH od data (word2),
	// At that point we migth have reached the end of frame already.
	// PKT_DATA is the (optional) remainder of the packet until the end.
	localparam					PKT_START	= 4;
	localparam					PKT_WORD2	= 2;
	localparam					PKT_DATA	= 1;
	localparam					SRC_PORT_OFF	= 16;

	// Local register(s) to keep track of state.
	reg [2:0]					state, next_state;
	reg						r_pkt_is_from_cpu;
	reg						r_pkt_is_from_cpu_next;
	reg						r_pktstate_out_wr_en;
	reg						r_pktstate_out_wr_en_next;

	// Birds on the wires.
	wire						w_pkt_is_from_cpu;
	wire						w_pktstate_out_empty;

	// Spaghetti
	assign w_pkt_is_from_cpu			=
	    i_tuser[SRC_PORT_OFF+1] | i_tuser[SRC_PORT_OFF+3] |
	    i_tuser[SRC_PORT_OFF+5] | i_tuser[SRC_PORT_OFF+7];
	assign o_pktstate_valid				= !w_pktstate_out_empty;


	// ---------------------------------------------------------------------
	// FIFO.
	fallthrough_small_fifo
	#(
		.WIDTH(1),
		.MAX_DEPTH_BITS(2)
	) pktstate_out
	// inputs and outputs
	(
		// Inputs
		.clk		(clk),
		.reset		(reset),
		.din		(r_pkt_is_from_cpu),	// goes in on 2nd cy
		.rd_en		(i_rd_from_magic),
		.wr_en		(r_pktstate_out_wr_en),
		// Outputs
		.dout		(o_pkt_is_from_cpu),
		.full		(),
		.nearly_full	(),
		.prog_full	(),
		.empty		(w_pktstate_out_empty)
	);

	// ---------------------------------------------------------------------
	// State machine.
	always @(*) begin
		// Make sure we always initialise to a (default) value.
		o_pkt_word1			=	0;
		o_pkt_word2			=	0;
		next_state			=	state;
		r_pkt_is_from_cpu_next		=	r_pkt_is_from_cpu;
		r_pktstate_out_wr_en_next	=	0;

		case (state)
		PKT_START: begin
			if (i_tvalid) begin
				// Signal stage output.
				o_pkt_word1 = 1;

				if (w_pkt_is_from_cpu) begin
					r_pkt_is_from_cpu_next = 1;
				end else begin
					r_pkt_is_from_cpu_next = 0;
				end
				r_pktstate_out_wr_en_next = 1;

				// Adavance state.
				next_state = PKT_WORD2;
			end
		end

		PKT_WORD2: begin
			if (i_tvalid) begin
				// Signal stage output.
				o_pkt_word2 = 1;

				// In case of min-size frame, must shortcut
				// back to initial state awaiting new packet.
				// otherwise we'll go to passthrough state.
				if (i_tlast)
					next_state = PKT_START;
				else
					next_state = PKT_DATA;
			end
		end

		// Passthrough state; wait for the end of packet.
		PKT_DATA: begin
			// If we hit the end of packet, await a new one.
			if (i_tvalid & i_tlast)
				next_state = PKT_START;
		end
		endcase
	end


	// ---------------------------------------------------------------------
	// Clocked work:
	// reset or advance state machine.
	always @(posedge clk) begin
		if (reset) begin
			state			<=	PKT_START;
			r_pkt_is_from_cpu	<=	0;
			r_pktstate_out_wr_en	<=	0;
		end else begin
			state			<=	next_state;
			r_pkt_is_from_cpu	<=	r_pkt_is_from_cpu_next;
			r_pktstate_out_wr_en	<=	r_pktstate_out_wr_en_next;
		end
	end

// -----------------------------------------------------------------------------

endmodule // pktstate
