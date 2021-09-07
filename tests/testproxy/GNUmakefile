PROJECT_ROOT= ../..
TESTPROXY:= ~/.cargo/bin/testproxy

TESTPROXY_VERSION=$(shell $(TESTPROXY) -V)
ifneq ($(TESTPROXY_VERSION),testproxy 0.0.3)
$(error Use Testproxy v0.0.3 with this version of SSLproxy, found $(TESTPROXY_VERSION))
endif

ifeq ($(findstring -DWITHOUT_USERAUTH,$(shell $(PROJECT_ROOT)/src/sslproxy -V 2>&1 | grep "Features: ")),-DWITHOUT_USERAUTH)
$(error End-to-end tests need UserAuth enabled, disable WITHOUT_USERAUTH feature in main makefile and try again)
endif

all: test

buildsslproxy:
	$(MAKE) -C $(PROJECT_ROOT)

buildlp:
	$(MAKE) -C lp

# XXX: How to build sslproxy before setting the vars? Otherwise, we depend on the main makefile to have already built it.
test: SSL_PROTOS=$(shell $(PROJECT_ROOT)/src/sslproxy -V 2>&1 | grep "SSL/TLS protocol availability")
test: TLS11=$(findstring tls11,$(SSL_PROTOS))
test: TLS13=$(findstring tls13,$(SSL_PROTOS))
test: SSLPROXY_CONF=$(if $(TLS13),sslproxy.conf,sslproxy_no_tls13.conf)
test: SSLPROXY_CONF:=$(if $(TLS11),$(SSLPROXY_CONF),sslproxy_no_tls11.conf)
test: SSLPROXY_COMMAND=$(PROJECT_ROOT)/src/sslproxy -f $(SSLPROXY_CONF) -o Debug=no -o Daemon=yes -o User=nobody
test: TESTHARNESS=$(if $(TLS13),testharness.json,testharness_no_tls13.json)
test: TESTHARNESS:=$(if $(TLS11),$(TESTHARNESS),testharness_no_tls11.json)
test: buildsslproxy buildlp
	sudo LD_LIBRARY_PATH=$(LD_LIBRARY_PATH) ./lp/lp -f ./lp/lp.conf -o Debug=no -o Daemon=yes -o User=nobody
	sudo LD_LIBRARY_PATH=$(LD_LIBRARY_PATH) $(SSLPROXY_COMMAND)
	$(TESTPROXY) -f $(TESTHARNESS) -l 4
	sudo pkill sslproxy
	sudo pkill lp

test_split: SSL_PROTOS=$(shell $(PROJECT_ROOT)/src/sslproxy -V 2>&1 | grep "SSL/TLS protocol availability")
test_split: TLS11=$(findstring tls11,$(SSL_PROTOS))
test_split: TLS13=$(findstring tls13,$(SSL_PROTOS))
test_split: SSLPROXY_CONF=$(if $(TLS13),sslproxy.conf,sslproxy_no_tls13.conf)
test_split: SSLPROXY_CONF:=$(if $(TLS11),$(SSLPROXY_CONF),sslproxy_no_tls11.conf)
test_split: SSLPROXY_COMMAND=$(PROJECT_ROOT)/src/sslproxy -n -f $(SSLPROXY_CONF) -o Debug=no -o Daemon=yes -o User=nobody
test_split: TESTHARNESS=$(if $(TLS13),testharness_split.json,testharness_split_no_tls13.json)
test_split: TESTHARNESS:=$(if $(TLS11),$(TESTHARNESS),testharness_split_no_tls11.json)
test_split: buildsslproxy
	sudo LD_LIBRARY_PATH=$(LD_LIBRARY_PATH) $(SSLPROXY_COMMAND)
	$(TESTPROXY) -f $(TESTHARNESS) -l 4
	sudo pkill sslproxy

travis: test

clean:
	$(MAKE) -C $(PROJECT_ROOT) clean
	$(MAKE) -C lp clean

FORCE:

.PHONY: all clean buildsslproxy buildlp test test_split travis

