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

		// In-HW access for lookups.
		// Destination address to lookup.
		input [31:0]				i_ipv4_arp_lut_ipv4_daddr,
		input					i_ipv4_arp_lut_ipv4_daddr_valid,
		// Is the address local?
		output reg				o_ipv4_arp_lut_ipv4_eth_addr_found,
		output reg[MAC_WIDTH-1:0]		o_ipv4_arp_lut_ipv4_eth_addr
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

	integer					i, j;

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
				ipv4_arp_table_eth[i]  <= {(2*32){1'b0}};
				ipv4_arp_table_ipv4[i] <= {(1*32){1'b0}};
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
	localparam				FIRST_STAGE	= 1'b1;
	localparam				SECOND_STAGE	= 1'b0;

	reg					state, state_next;
	reg [31:0]				r_daddr;

	// ---------------------------------------------------------------------
	// Clocked work:
	// Split into two states to (a) make synth more happy and (b) we want
	// the delay anyway, well not really for this as two cam lookups
	// would be possible in two clock cycles in the future.
	always @(posedge clk) begin
		state_next				= state;

		if (reset) begin
			o_ipv4_arp_lut_ipv4_eth_addr = 48'h000000000000;
			o_ipv4_arp_lut_ipv4_eth_addr_found = 0;
			r_daddr = 32'h00000000;
			state = FIRST_STAGE;

		end else begin
			case (state) 
			FIRST_STAGE: begin
				if (i_ipv4_arp_lut_ipv4_daddr_valid) begin
					o_ipv4_arp_lut_ipv4_eth_addr = 48'h000000000000;
					o_ipv4_arp_lut_ipv4_eth_addr_found = 0;
					r_daddr = i_ipv4_arp_lut_ipv4_daddr;
					for (j = 0; j < 16; j = j + 1) begin
						if (!o_ipv4_arp_lut_ipv4_eth_addr_found && ipv4_arp_table_ipv4[j] == r_daddr) begin
							o_ipv4_arp_lut_ipv4_eth_addr_found = 1;
							o_ipv4_arp_lut_ipv4_eth_addr = ipv4_arp_table_eth[j];
						end
					end
					state_next = SECOND_STAGE;	
				end
			end

			SECOND_STAGE: begin
				for (j = 16; j < 32; j = j + 1) begin
					if (!o_ipv4_arp_lut_ipv4_eth_addr_found && ipv4_arp_table_ipv4[j] == r_daddr) begin
						o_ipv4_arp_lut_ipv4_eth_addr_found = 1;
						o_ipv4_arp_lut_ipv4_eth_addr = ipv4_arp_table_eth[j];
					end
				end
				state_next = FIRST_STAGE;	
			end

			//default: begin
			//	o_ipv4_arp_lut_ipv4_eth_addr_found = 0;
			//	o_ipv4_arp_lut_ipv4_eth_addr = 48'h000000000000;
			//end
			endcase
		end

		state = state_next;
	end

// -----------------------------------------------------------------------------

endmodule // ipv4_arp_lut