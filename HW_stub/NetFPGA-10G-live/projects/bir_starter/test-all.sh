#!/bin/sh

# sim or hw
MODE=hw
MODE=sim

set -e
set -x

case "${NF_ROOT}" in
"")	echo "ERROR: NF_ROOT not set" >&2
	exit 1
	;;
esac
case "${NF_DESIGN_DIR}" in
"")	echo "ERROR: NF_DESIGN_DIR not set" >&2
	exit 1
	;;
esac

DATETIME=`date +%Y%m%d-%H%M%S`
LOG=$NF_DESIGN_DIR/test-${DATETIME}

pushd $NF_DESIGN_DIR/test

#ls -1 | egrep -v 'both_(pkt_arp|reg_aio|stage7_fourtoone|stage9_floodingsw|simple_forwarding)' | awk -F_ '/^both_/ { printf "/usr/bin/time ./nf_test.py sim --major %s --minor %s --isim\n", $2, $3 }'
ls -1 | egrep -v 'both_(pkt_arp|reg_aio|stage7_fourtoone|stage9_floodingsw|simple_forwarding)' | awk -F_ '/^both_/ { printf "%s %s\n", $2, $3 }' | \
while read maj min; do

	echo "==> Running test ${maj} ${min}"
	pushd $NF_ROOT/tools/bin
	case ${MODE} in
	sim) /usr/bin/time ./nf_test.py sim --major ${maj} --minor ${min} --isim >> ${LOG} 2>&1 ;;
	hw) /usr/bin/time ./nf_test.py hw --major ${maj} --minor ${min} >> ${LOG}-${maj}_${min} 2>&1 ;;
	*) echo "ERROR: mode ${MODE} not supported." >&2; exit 2 ;;
	esac
	popd

	case ${MODE} in
	sim)	$NF_ROOT/tools/scripts/nf10_sim_registers_axi_logs.py > ${LOG}-${maj}_${min}_regs.log 2>&1
		$NF_ROOT/tools/scripts/nf10_sim_reconcile_axi_logs.py > ${LOG}-${maj}_${min}_pkts.log 2>&1
		;;
	hw)	../dump-regs >> ${LOG}-${maj}_${min} 2>&1
		;;
	esac
done

popd

# end
