#-------------------------------------------------------------------------------
# File: Makefile
# Date: Tue Feb 03 15:03:51 PST 2004
# Author: Martin Casado
# Modified for Mininet compatibility,
#         August 2013
#         Matthew Ireland <mti20@cam.ac.uk>
#
# Note: This Makefile requires GNU make.
#
# (c) 2001,2000 Stanford University
#
#-------------------------------------------------------------------------------

all : sr

APP = sr
APP_TPP = sr_tpp
CC  = gcc

# build the pool version
pool :
	gmake --no-print-directory clean-byproducts
	gmake --no-print-directory all

# build the thread-per-packet version
tpp :
	gmake --no-print-directory clean-byproducts
	gmake APP=$(APP_TPP) THREAD_SCHEME=$(USE_THREAD_PER_PACKET) --no-print-directory all

both : pool tpp

# MODE controls whether the router gets/sends packets from/to the NetFPGA, mininet
# or manually
# Note how similar 'MANUAL' and 'MININET' look, and remember they're different!
MODE_NETFPGA = -D_CPUMODE_
MODE_MININET = -DMININET_MODE
MODE_MANUAL  = -D_MANUAL_MODE_
MODE = $(MODE_NETFPGA)

#the next lines control whether to use one thread per packet or a worker pool
USE_THREAD_POOL       = -DNUM_WORKER_THREADS=1   # use a thread pool w/ this # of workers
USE_THREAD_PER_PACKET = -D_THREAD_PER_PACKET_    # use one thread per packet (no thread pool)
THREAD_SCHEME = $(USE_THREAD_POOL)

include Makefile.common
PERF=-g -Wall -D_DEBUG_
#PERF=-O3 -Wall
CFLAGS = -D_GNU_SOURCE $(PERF) $(ARCH) -I lwtcp -I cli -I common $(MODE) $(THREAD_SCHEME) $(MORE_FLAGS)
USER_LIBS=libsr_base.a liblwtcp.a

PFLAGS= -follow-child-processes=yes -cache-dir=/tmp/${USER}
PURIFY= purify ${PFLAGS}

#------------------------------------------------------------------------------

RESTRICTED_CLI_SRCS = cli/cli.c cli/cli_help.c cli/cli_ping.c\
                      cli/search_state.c cli/cli_local.c\
                      cli/lex.yy.c cli/y.tab.c
CLI_SRCS = cli/cli_main.c cli/socket_helper.c $(RESTRICTED_CLI_SRCS) sr_lwtcp_glue.c
CLI_OBJS = $(patsubst cli/%.c, %.o, $(CLI_SRCS))

cli/lex.yy.c cli/lex.yy.o :
	make -C cli lex.yy.o

cli/y.tab.c cli/y.tab.o :
	make -C cli y.tab.o

#------------------------------------------------------------------------------
LWTCP_SRCS = lwtcp/tcp.c lwtcp/tcp_input.c lwtcp/tcp_output.c\
             lwtcp/mem.c lwtcp/memp.c lwtcp/stats.c lwtcp/sys.c\
             lwtcp/inet.c lwtcp/pbuf.c lwtcp/sys_arch.c\
             lwtcp/sockets.c lwtcp/api_lib.c lwtcp/api_msg.c\
             lwtcp/transport_subsys.c lwtcp/udp.c lwtcp/icmp.c lwtcp/ip_addr.c\
             lwtcp/err.c

LWTCP_OBJS = $(patsubst lwtcp/%.c, %.o, $(LWTCP_SRCS))

liblwtcp.a : $(LWTCP_OBJS)
	ar rcu liblwtcp.a $(LWTCP_OBJS)

#------------------------------------------------------------------------------
SR_BASE_SRCS = sr_base.c sr_dumper.c sr_integration.c sr_lwtcp_glue.c\
               sr_cpu_extension_nf2.c real_socket_helper.c \
               debug.c sr_mininet_extension.c

SR_BASE_OBJS = $(patsubst %.c,%.o,$(SR_BASE_SRCS)) common/nf10util.o common/nf_util.o

libsr_base.a : $(SR_BASE_OBJS)
	ar rcu libsr_base.a $(SR_BASE_OBJS)
#------------------------------------------------------------------------------


#------------------------------------------------------------------------------
SR_SRCS_MAIN = sr_main.c

SR_SRCS_BASE =  sr_router.c sr_common.c \
	        sr_interface.c \
	        sr_work_queue.c \
	        ip.c arp.c my_icmp.c routing.c policy.c sha256c.c

SR_SRCS = $(SR_SRCS_MAIN) $(SR_SRCS_BASE)

SR_OBJS = $(patsubst %.c,%.o,$(SR_SRCS)) $(CLI_OBJS)

sr : $(SR_OBJS) $(USER_LIBS)
	$(CC) $(CFLAGS) -o $(APP) $(SR_OBJS) $(LIBS) $(USER_LIBS)
#------------------------------------------------------------------------------

# CLI Test targe
TEST_CLI_APP  = cli/test_cli.exe
TEST_CLI_SRCS = cli/cli_test.c $(SR_SRCS_BASE) $(RESTRICTED_CLI_SRCS)
TEST_CLI_OBJS = $(patsubst %.c,%.o,$(TEST_CLI_SRCS)) cli/socket_helper_to_stderr.o

cli/socket_helper_to_stderr.o : cli/socket_helper.c cli/socket_helper.h
	make -C cli socket_helper_to_stderr.o

test_cli.exe: $(TEST_CLI_OBJS) $(USER_LIBS)
	$(CC) $(CFLAGS) -D_STANDALONE_CLI_ -o $(TEST_CLI_APP) $(TEST_CLI_OBJS) $(LIBS) $(USER_LIBS)                            #  -o $(TEST_CLI_APP) $(TEST_CLI_OBJS) $(LIBS) $(USER_LIBS)  #-D_STANDALONE_CLI_ -o $(TEST_CLI_APP) $(TEST_CLI_OBJS) $(LIBS) $(USER_LIBS)
#------------------------------------------------------------------------------
ALL_SRCS   = $(sort $(SR_SRCS) $(SR_BASE_SRCS) $(LWTCP_SRCS) $(CLI_SRCS))

ALL_LWTCP_SRCS = $(filter lwtcp/%.c, $(ALL_SRCS))
ALL_CLI_SRCS   = $(filter cli/%.c, $(ALL_SRCS))

ALL_SR_SRCS_NO_LWTCP = $(filter-out lwtcp/%.c, $(ALL_SRCS))
ALL_SR_SRCS    = $(filter-out cli/%.c, $(ALL_SR_SRCS_NO_LWTCP))

ALL_LWTCP_OBJS = $(patsubst lwtcp/%.c,%.o, $(ALL_LWTCP_SRCS))
ALL_CLI_OBJS   = $(patsubst cli/%.c,%.o, $(ALL_CLI_SRCS))
ALL_SR_OBJS    = $(patsubst %.c,%.o, $(ALL_SR_SRCS))

ALL_LWTCP_DEPS = $(patsubst lwtcp/%.c,.%.d,$(ALL_LWTCP_SRCS))
ALL_CLI_DEPS   = $(patsubst cli/%.c,.%.d,$(ALL_CLI_SRCS))
ALL_SR_DEPS    = $(patsubst %.c,.%.d,$(ALL_SR_SRCS))

$(ALL_SR_OBJS) : %.o : %.c
	$(CC) -c $(CFLAGS) $< -o $@
$(ALL_LWTCP_OBJS) : %.o : ./lwtcp/%.c
	$(CC) -c $(CFLAGS) $< -o $@
$(ALL_CLI_OBJS) : %.o : ./cli/%.c
	$(CC) -c $(CFLAGS) $< -o $@

$(ALL_LWTCP_DEPS) : .%.d : ./lwtcp/%.c
	$(CC) -MM $(CFLAGS) -I lwtcp/ $<  > $@
$(ALL_CLI_DEPS) : .%.d : ./cli/%.c
	$(CC) -MM $(CFLAGS) -I cli/ $<  > $@
$(ALL_SR_DEPS) : .%.d : %.c
	$(CC) -MM $(CFLAGS) -I lwtcp/ $<  > $@

include $(ALL_LWTCP_DEPS)
include $(ALL_CLI_DEPS)
include $(ALL_SR_DEPS)

#------------------------------------------------------------------------------

#------------------------------------------------------------------------------
.PHONY : clean clean-deps dist

clean-byproducts:
	rm -f *.o *~ core.* *.dump *.tar tags *.a test_arp_subsystem\
          lwcli lwtcpsr sr_base.tar.gz

clean: clean-byproducts
	rm -f $(APP) $(APP_TPP)
	make -C cli clean

clean-deps:
	rm -f .*.d

dist: clean clean-deps
	(cd ..; tar --exclude-from=base/exclude -cvf sr_base.tar base/; gzip sr_base.tar; mv\
    sr_base.tar.gz base/)

tags:
	ctags *.c
#------------------------------------------------------------------------------
