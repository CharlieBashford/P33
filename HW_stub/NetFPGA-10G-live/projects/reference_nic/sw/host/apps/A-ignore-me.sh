#!/bin/sh

# 10.0.1.1 	0.0.0.0 	255.255.255.255   	02
# 10.0.2.1 	0.0.0.0 	255.255.255.255   	08
# 10.0.3.1 	0.0.0.0 	255.255.255.255   	20
# 10.0.1.2 	0.0.0.0 	255.255.255.255   	02
# 10.0.5.2 	0.0.0.0 	255.255.255.255   	02
# 10.0.2.0 	0.0.0.0 	255.255.255.0   	04
# 10.0.3.0 	0.0.0.0 	255.255.255.0   	10
# 10.0.5.0 	10.0.3.2 	255.255.255.0   	10
# 10.0.6.0 	10.0.3.2 	255.255.255.0   	10

zero()
{
	for i in `seq 0 31`; do
		x=`printf "0x%x" ${i}`
		#./wraxi 0x74808000 0x0a000102	#10.0.1.2
		#./wraxi 0x74808004 0xffffffff	#255.255.255.255
		#./wraxi 0x74808008 0x0a000301	#10.0.3.1
		#./wraxi 0x7480800c 0x20		#nf2
		./wraxi 0x74808000 0x0 > /dev/null
		./wraxi 0x74808004 0x0 > /dev/null
		./wraxi 0x74808008 0x0 > /dev/null
		./wraxi 0x7480800c 0x0 > /dev/null
		./wraxi 0x74808010 ${x} > /dev/null
	done
}
zero

p()
{
	i=`printf "0x%x" ${IDX}`
	p=$1
	m=$2
	n=$3
	t=$4
	printf "W: %s %s %s %s %s\n" $i $p $m $n $t
	./wraxi 0x74808000 ${p} > /dev/null
	./wraxi 0x74808004 ${m} > /dev/null
	./wraxi 0x74808008 ${n} > /dev/null
	./wraxi 0x7480800c ${t} > /dev/null
	./wraxi 0x74808010 ${i} > /dev/null

	IDX=$((IDX + 1))
}

IDX=0
# Locally connected destinations
p 0x0a000101 0xffffffff 0x0 0x02
p 0x0a000201 0xffffffff 0x0 0x08
p 0x0a000301 0xffffffff 0x0 0x20
# Policy
p 0x0a000102 0xffffffff 0x0a000101 0x02
p 0x0a000502 0xffffffff 0x0a000501 0x10
#p 0x0a000102 0xffffffff 0x7f000001 0x02
#p 0x0a000502 0xffffffff 0x7f000001 0x10
#p 0x0a000102 0xffffffff 0x0a000201 0x02
#p 0x0a000502 0xffffffff 0x0a000201 0x10
#p 0x0a000102 0xffffffff 0x0 0x02
#p 0x0a000502 0xffffffff 0x0 0x10
# Connected
p 0x0a000200 0xffffff00 0x0 0x04
p 0x0a000300 0xffffff00 0x0 0x10
# Dynamic
p 0x0a000500 0xffffff00 0x0a000302 0x10
p 0x0a000600 0xffffff00 0x0a000302 0x10


# end





