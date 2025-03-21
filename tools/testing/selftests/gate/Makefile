# SPDX-License-Identifier: GPL-2.0
CFLAGS += -Wall -pthread $(KHDR_INCLUDES)
LDLIBS += -lpthread

LOCAL_HDRS += $(selfdir)/gate/gate_sys.h
TEST_GEN_PROGS := gate_demo gate_wait gate_wake
include ../lib.mk
