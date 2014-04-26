/*
TDATA   1
----------------------------------------

start bit
255		dmac
207		smac
159		ethertype
143		payload	{ IP ... }

143		IP version | IHL
135		TOS
127		Total Length
111		ID
 95		Flags, Fragment Offset
 79		TTL
 71		Protocol
 63		Header Csum
 47		SrcIP
 15		DstIP[3:2]

TDATA   2
----------------------------------------

start bit
255		DstIP[1:0]
239		[IP {options, padding}, ULP]

# end */
