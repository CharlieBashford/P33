/*******************************************************************************
 *
 *  NetFPGA-10G http://www.netfpga.org
 *
 *  File:
 *        nf10_input_arbiter.v
 *
 *  Library:
 *        hw/std/pcores/nf10_input_arbiter_v1_00_a
 *
 *  Module:
 *        nf10_input_arbiter
 *
 *  Author:
 *        Adam Covington
 *
 *  Description:
 *        Round Robin arbiter (N inputs to 1 output)
 *        Inputs have a parameterizable width
 *
 *
 *----------------------------------------------------------------------
 *  Current status: Currently only reads from input 0 which corresponds to                 
 *                  the first physical network port
 *
 *  To do: Modify the code below to implement round-robin servicing of all
 *         queues. See comments inline (denoted by FIXME)
 *----------------------------------------------------------------------
 *
 *  Copyright notice:
 *        Copyright (C) 2010, 2011 The Board of Trustees of The Leland Stanford
 *                                 Junior University
 *
 *  Licence:
 *        This file is part of the NetFPGA 10G development base package.
 *
 *        This file is free code: you can redistribute it and/or modify it under
 *        the terms of the GNU Lesser General Public License version 2.1 as
 *        published by the Free Software Foundation.
 *
 *        This package is distributed in the hope that it will be useful, but
 *        WITHOUT ANY WARRANTY; without even the implied warranty of
 *        MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *        Lesser General Public License for more details.
 *
 *        You should have received a copy of the GNU Lesser General Public
 *        License along with the NetFPGA source package.  If not, see
 *        http://www.gnu.org/licenses/.
 *
 */

module nf10_input_arbiter
#(
    // Master AXI Stream Data Width
    parameter C_M_AXIS_DATA_WIDTH=256,
    parameter C_S_AXIS_DATA_WIDTH=256,
    parameter C_M_AXIS_TUSER_WIDTH=128,
    parameter C_S_AXIS_TUSER_WIDTH=128,
    parameter NUM_QUEUES=5
)
(
    // Part 1: System side signals
    // Global Ports
    input axi_aclk,
    input axi_resetn,

    // Master Stream Ports (interface to data path)
    output [C_M_AXIS_DATA_WIDTH - 1:0] m_axis_tdata,
    output [((C_M_AXIS_DATA_WIDTH / 8)) - 1:0] m_axis_tstrb,
    output [C_M_AXIS_TUSER_WIDTH-1:0] m_axis_tuser,
    output m_axis_tvalid,
    input  m_axis_tready,
    output m_axis_tlast,

    // Slave Stream Ports (interface to RX queues)
    input [C_S_AXIS_DATA_WIDTH - 1:0] s_axis_tdata_0,
    input [((C_S_AXIS_DATA_WIDTH / 8)) - 1:0] s_axis_tstrb_0,
    input [C_S_AXIS_TUSER_WIDTH-1:0] s_axis_tuser_0,
    input  s_axis_tvalid_0,
    output s_axis_tready_0,
    input  s_axis_tlast_0,

    input [C_S_AXIS_DATA_WIDTH - 1:0] s_axis_tdata_1,
    input [((C_S_AXIS_DATA_WIDTH / 8)) - 1:0] s_axis_tstrb_1,
    input [C_S_AXIS_TUSER_WIDTH-1:0] s_axis_tuser_1,
    input  s_axis_tvalid_1,
    output s_axis_tready_1,
    input  s_axis_tlast_1,

    input [C_S_AXIS_DATA_WIDTH - 1:0] s_axis_tdata_2,
    input [((C_S_AXIS_DATA_WIDTH / 8)) - 1:0] s_axis_tstrb_2,
    input [C_S_AXIS_TUSER_WIDTH-1:0] s_axis_tuser_2,
    input  s_axis_tvalid_2,
    output s_axis_tready_2,
    input  s_axis_tlast_2,

    input [C_S_AXIS_DATA_WIDTH - 1:0] s_axis_tdata_3,
    input [((C_S_AXIS_DATA_WIDTH / 8)) - 1:0] s_axis_tstrb_3,
    input [C_S_AXIS_TUSER_WIDTH-1:0] s_axis_tuser_3,
    input  s_axis_tvalid_3,
    output s_axis_tready_3,
    input  s_axis_tlast_3,

    input [C_S_AXIS_DATA_WIDTH - 1:0] s_axis_tdata_4,
    input [((C_S_AXIS_DATA_WIDTH / 8)) - 1:0] s_axis_tstrb_4,
    input [C_S_AXIS_TUSER_WIDTH-1:0] s_axis_tuser_4,
    input  s_axis_tvalid_4,
    output s_axis_tready_4,
    input  s_axis_tlast_4
);

   function integer log2;
      input integer number;
      begin
         log2=0;
         while(2**log2<number) begin
            log2=log2+1;
         end
      end
   endfunction // log2

   // ------------ Internal Params --------

   parameter NUM_QUEUES_WIDTH = log2(NUM_QUEUES);

   parameter NUM_STATES = 1;
   parameter IDLE = 0;
   parameter WR_PKT = 1;

   localparam MAX_PKT_SIZE = 2000; // In bytes
   localparam IN_FIFO_DEPTH_BIT = log2(MAX_PKT_SIZE/(C_M_AXIS_DATA_WIDTH / 8));

   // ------------- Regs/ wires -----------

   wire [NUM_QUEUES-1:0]               nearly_full;
   wire [NUM_QUEUES-1:0]               empty;
   wire [C_M_AXIS_DATA_WIDTH-1:0]        in_tdata      [NUM_QUEUES-1:0];
   wire [((C_M_AXIS_DATA_WIDTH/8))-1:0]  in_tstrb      [NUM_QUEUES-1:0];
   wire [C_M_AXIS_TUSER_WIDTH-1:0]             in_tuser      [NUM_QUEUES-1:0];
   wire [NUM_QUEUES-1:0] 	       in_tvalid;
   wire [NUM_QUEUES-1:0]               in_tlast;
   wire [C_M_AXIS_TUSER_WIDTH-1:0]             fifo_out_tuser[NUM_QUEUES-1:0];
   wire [C_M_AXIS_DATA_WIDTH-1:0]        fifo_out_tdata[NUM_QUEUES-1:0];
   wire [((C_M_AXIS_DATA_WIDTH/8))-1:0]  fifo_out_tstrb[NUM_QUEUES-1:0];
   wire [NUM_QUEUES-1:0] 	       fifo_out_tlast;
   wire                                fifo_tvalid;
   wire                                fifo_tlast;
   reg [NUM_QUEUES-1:0]                rd_en;

   wire [NUM_QUEUES_WIDTH-1:0]         cur_queue_plus1;
   reg [NUM_QUEUES_WIDTH-1:0]          cur_queue;
   reg [NUM_QUEUES_WIDTH-1:0]          cur_queue_next;

   reg [NUM_STATES-1:0]                state;
   reg [NUM_STATES-1:0]                state_next;

   // ------------ Modules -------------

   // FIXME:
   // This code currently generates a single fallthrough small fifo for
   // buffering data coming from input 0.
   //
   // Use a generate statement with a for loop to generate fifos for each
   // of the input ports

   // XXX-BZ generate 5 of those and prentend to care about DMA as well.
   genvar idx;
   generate
     for (idx = 0; idx < NUM_QUEUES; idx = idx + 1) begin:infifos
       fallthrough_small_fifo
		#( .WIDTH(C_M_AXIS_DATA_WIDTH+C_M_AXIS_TUSER_WIDTH+C_M_AXIS_DATA_WIDTH/8+1),
		   .MAX_DEPTH_BITS(IN_FIFO_DEPTH_BIT))
	      in_arb_fifo
		(// Outputs
		 .dout                           ({fifo_out_tlast[idx], fifo_out_tuser[idx], fifo_out_tstrb[idx], fifo_out_tdata[idx]}),
		 .full                           (),
		 .nearly_full                    (nearly_full[idx]),
		 .prog_full                      (),
		 .empty                          (empty[idx]),
		 // Inputs
		 .din                            ({in_tlast[idx], in_tuser[idx], in_tstrb[idx], in_tdata[idx]}),
		 .wr_en                          (in_tvalid[idx] & ~nearly_full[idx]),
		 .rd_en                          (rd_en[idx]),
		 .reset                          (~axi_resetn),
		 .clk                            (axi_aclk));
     end
   endgenerate

   // ------------- Logic ------------

   assign in_tdata[0]        = s_axis_tdata_0;
   assign in_tstrb[0]        = s_axis_tstrb_0;
   assign in_tuser[0]        = s_axis_tuser_0;
   assign in_tvalid[0]       = s_axis_tvalid_0;
   assign in_tlast[0]        = s_axis_tlast_0;
   assign s_axis_tready_0    = !nearly_full[0];

   assign in_tdata[1]        = s_axis_tdata_1;
   assign in_tstrb[1]        = s_axis_tstrb_1;
   assign in_tuser[1]        = s_axis_tuser_1;
   assign in_tvalid[1]       = s_axis_tvalid_1;
   assign in_tlast[1]        = s_axis_tlast_1;
   assign s_axis_tready_1    = !nearly_full[1];

   assign in_tdata[2]        = s_axis_tdata_2;
   assign in_tstrb[2]        = s_axis_tstrb_2;
   assign in_tuser[2]        = s_axis_tuser_2;
   assign in_tvalid[2]       = s_axis_tvalid_2;
   assign in_tlast[2]        = s_axis_tlast_2;
   assign s_axis_tready_2    = !nearly_full[2];

   assign in_tdata[3]        = s_axis_tdata_3;
   assign in_tstrb[3]        = s_axis_tstrb_3;
   assign in_tuser[3]        = s_axis_tuser_3;
   assign in_tvalid[3]       = s_axis_tvalid_3;
   assign in_tlast[3]        = s_axis_tlast_3;
   assign s_axis_tready_3    = !nearly_full[3];

   // XXX-BZ This is DMA and we don't care about it as we only do Port 0..3?
   // Well, let's pretend we do care.
   assign in_tdata[4]        = s_axis_tdata_4;
   assign in_tstrb[4]        = s_axis_tstrb_4;
   assign in_tuser[4]        = s_axis_tuser_4;
   assign in_tvalid[4]       = s_axis_tvalid_4;
   assign in_tlast[4]        = s_axis_tlast_4;
   assign s_axis_tready_4    = !nearly_full[4];

   // XXX-BZ so we also need to reduce the cur_queue tristate to 0..3
   // for rollover in case we do not want DMA to work, but we pretned
   // we want it working.
   assign cur_queue_plus1    = (cur_queue == NUM_QUEUES-1) ? 0 : cur_queue + 1;

   // XXX-BZ above we made the FIFOs output to all these wires but we
   // can only ever handle one (the current) port.  This needs to change
   // as otherwise we are reading into "nowhere in Idaho"(?) for the other 3.
   // XXX-BZ this is outside the "FIXME" comments.   I assume this was
   // left as an annoying exercise to the student;-)
   assign m_axis_tuser = fifo_out_tuser[cur_queue];
   assign m_axis_tdata = fifo_out_tdata[cur_queue];
   assign m_axis_tlast = fifo_out_tlast[cur_queue];
   assign m_axis_tstrb = fifo_out_tstrb[cur_queue];
   assign m_axis_tvalid = ~empty[cur_queue];

   // Main state machine to cycle through the inputs
   // and transfer data from an input to the output
   //
   // The state machine is in one of two states:
   //  1. IDLE -- not currently transferring a packet
   //             waiting for data on an input
   //  2. WR_PKT -- transferring a packet
   //               in this state looks to identify the
   //               EOP signal
   //
   // Combinational logic of state machine

   always @(*) begin
      /* Initially set the next state to the current state */
      state_next      = state;
      cur_queue_next  = cur_queue;
      rd_en           = 0;		// XXX-BZ read up; assumption: this sets the entire register to 0?

      // FIXME:
      //   Modify logic to look at more than just input 0
      //   Think about where to place logic that iterates through
      //   the inputs (and maybe make use of the cur_queue_plus1 signal)
      case(state)

        /* cycle between input queues until one is not empty */
        IDLE: begin
           if(!empty[cur_queue]) begin
              if(m_axis_tready) begin
	         $display("Begin of packet m_axis_tuser = 0x%x\n", m_axis_tuser);
                 state_next = WR_PKT;
                 rd_en[cur_queue] = 1;
              end
           end
           else
              cur_queue_next = cur_queue_plus1;
        end

        /* wait until eop */
        WR_PKT: begin
           /* if this is the last word then write it and get out */
           if(m_axis_tready & m_axis_tlast) begin
              state_next = IDLE;
	      rd_en[cur_queue] = 1;
              cur_queue_next = cur_queue_plus1;
           end
           /* otherwise read and write as usual */
           else if (m_axis_tready & !empty[cur_queue]) begin
              rd_en[cur_queue] = 1;
           end
        end // case: WR_PKT

      endcase // case(state)
   end // always @ (*)

   always @(posedge axi_aclk) begin
      if(~axi_resetn) begin
         state <= IDLE;
         cur_queue <= 0;
      end
      else begin
         state <= state_next;
         cur_queue <= cur_queue_next;
      end
   end

endmodule
