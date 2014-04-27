#!/bin/sh

#define XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_IP 0x74808000
#define XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_IP_MASK 0x74808004
#define XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_NEXT_HOP_IP 0x74808008
#define XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_OQ 0x7480800c
#define XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_WR_ADDR 0x74808010
#define XPAR_NF10_ROUTER_OUTPUT_PORT_LOOKUP_0_LPM_RD_ADDR 0x74808014

for i in `seq 0 31`; do
	x=`printf "0x%x" ${i}`
	./wraxi 0x74808014 ${x} > /dev/null 2>&1
	p=`./rdaxi  0x74808000 | awk -F= '/AXI/ { print $2 }'`
	m=`./rdaxi  0x74808004 | awk -F= '/AXI/ { print $2 }'`
	nh=`./rdaxi 0x74808008 | awk -F= '/AXI/ { print $2 }'`
	tu=`./rdaxi 0x7480800c | awk -F= '/AXI/ { print $2 }'`

	printf "%-2d %s %s %s %s %s\n" ${i} ${x} $p $m $nh $tu
done

# end
