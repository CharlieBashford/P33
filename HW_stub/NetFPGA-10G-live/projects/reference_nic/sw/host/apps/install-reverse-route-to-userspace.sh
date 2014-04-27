#!/bin/sh

p()
{
	local _i p m n t
	_i=`printf "0x%x" ${IDX}`
	p=$1
	m=$2
	n=$3
	t=$4
	printf "W: %s %s %s %s %s\n" $_i $p $m $n $t
	./wraxi 0x74808000 ${p} > /dev/null
	./wraxi 0x74808004 ${m} > /dev/null
	./wraxi 0x74808008 ${n} > /dev/null
	./wraxi 0x7480800c ${t} > /dev/null
	./wraxi 0x74808010 ${_i} > /dev/null

	IDX=$((IDX - 1))
}

IDX=31
for j in `seq 0 30 | sort -rn`; do
	x=`printf "0x%x" ${j}`
	./wraxi 0x74808014 ${x} > /dev/null 2>&1
	xp=`./rdaxi  0x74808000 | awk -F= '/AXI/ { print $2 }'`
	xm=`./rdaxi  0x74808004 | awk -F= '/AXI/ { print $2 }'`
	xnh=`./rdaxi 0x74808008 | awk -F= '/AXI/ { print $2 }'`
	xtu=`./rdaxi 0x7480800c | awk -F= '/AXI/ { print $2 }'`

	printf "%-2d %s %s %s %s %s\n" ${j} ${x} $xp $xm $xnh $xtu
	p $xp $xm $xnh $xtu
done

IDX=0
p 0x0a000102 0xffffffff 0x0a000101 0x02

