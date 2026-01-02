PROJECT_ROOT= ../..
TESTPROXY:= ~/.cargo/bin/testproxy

TESTPROXY_VERSION=$(shell $(TESTPROXY) -V)
ifneq ($(TESTPROXY_VERSION),testproxy 0.0.5)
$(error Use Testproxy v0.0.5 with this version of SSLproxy, found $(TESTPROXY_VERSION))
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
realtest: SSL_PROTOS=$(shell $(PROJECT_ROOT)/src/sslproxy -V 2>&1 | grep "SSL/TLS protocol availability")
realtest: TLS11=$(findstring tls11,$(SSL_PROTOS))
realtest: TLS13=$(findstring tls13,$(SSL_PROTOS))
realtest: OPENSSL=$(shell $(PROJECT_ROOT)/src/sslproxy -V 2>&1 | grep "compiled against OpenSSL")
realtest: OPENSSL3=$(findstring "OpenSSL 3.",$(OPENSSL))
realtest: SSLPROXY_CONF=$(if $(TLS13),sslproxy.conf,sslproxy_no_tls13.conf)
realtest: SSLPROXY_CONF:=$(if $(TLS11),$(SSLPROXY_CONF),sslproxy_no_tls11.conf)
realtest: SSLPROXY_CONF:=$(if $(OPENSSL3),$(SSLPROXY_CONF),sslproxy_openssl3.conf)
realtest: SSLPROXY_COMMAND=$(PROJECT_ROOT)/src/sslproxy -f $(SSLPROXY_CONF) -o Debug=no -o Daemon=yes -o User=nobody
realtest: TESTHARNESS=$(if $(TLS13),testharness.json,testharness_no_tls13.json)
realtest: TESTHARNESS:=$(if $(TLS11),$(TESTHARNESS),testharness_no_tls11.json)
realtest: TESTHARNESS:=$(if $(OPENSSL3),$(TESTHARNESS),testharness_openssl3.json)
#realtest: SKIP_TESTHARNESS=2
realtest: buildsslproxy buildlp
	sudo LD_LIBRARY_PATH=$(LD_LIBRARY_PATH) ./lp/lp -f ./lp/lp.conf -o Debug=no -o Daemon=yes -o User=nobody
	sudo LD_LIBRARY_PATH=$(LD_LIBRARY_PATH) $(SSLPROXY_COMMAND)
	$(TESTPROXY) -f $(TESTHARNESS) -l 4 --skip-test-harness $(SKIP_TESTHARNESS)

test:
	sh -c "trap 'trap - 0 1 2 3 6 15; echo Clean up on exit; sudo pkill \"sslproxy|lp\"' 0 1 2 3 6 15; $(MAKE) realtest"

realtest_split: SSL_PROTOS=$(shell $(PROJECT_ROOT)/src/sslproxy -V 2>&1 | grep "SSL/TLS protocol availability")
realtest_split: TLS11=$(findstring tls11,$(SSL_PROTOS))
realtest_split: TLS13=$(findstring tls13,$(SSL_PROTOS))
realtest_split: OPENSSL=$(shell $(PROJECT_ROOT)/src/sslproxy -V 2>&1 | grep "compiled against OpenSSL")
realtest_split: OPENSSL3=$(findstring "OpenSSL 3.",$(OPENSSL))
realtest_split: SSLPROXY_CONF=$(if $(TLS13),sslproxy.conf,sslproxy_no_tls13.conf)
realtest_split: SSLPROXY_CONF:=$(if $(TLS11),$(SSLPROXY_CONF),sslproxy_no_tls11.conf)
realtest_split: SSLPROXY_CONF:=$(if $(OPENSSL3),$(SSLPROXY_CONF),sslproxy_openssl3.conf)
realtest_split: SSLPROXY_COMMAND=$(PROJECT_ROOT)/src/sslproxy -n -f $(SSLPROXY_CONF) -o Debug=no -o Daemon=yes -o User=nobody
realtest_split: TESTHARNESS=$(if $(TLS13),testharness_split.json,testharness_split_no_tls13.json)
realtest_split: TESTHARNESS:=$(if $(TLS11),$(TESTHARNESS),testharness_split_no_tls11.json)
realtest_split: TESTHARNESS:=$(if $(OPENSSL3),$(TESTHARNESS),testharness_split_openssl3.json)
realtest_split: buildsslproxy buildlp
	sudo LD_LIBRARY_PATH=$(LD_LIBRARY_PATH) ./lp/lp -f ./lp/lp.conf -o Debug=no -o Daemon=yes -o User=nobody
	sudo LD_LIBRARY_PATH=$(LD_LIBRARY_PATH) $(SSLPROXY_COMMAND)
	$(TESTPROXY) -f $(TESTHARNESS) -l 4

test_split:
	sh -c "trap 'trap - 0 1 2 3 6 15; echo Clean up on exit; sudo pkill \"sslproxy|lp\"' 0 1 2 3 6 15; $(MAKE) realtest_split"

travis: test

clean:
	$(MAKE) -C $(PROJECT_ROOT) clean
	$(MAKE) -C lp clean

FORCE:

.PHONY: all clean buildsslproxy buildlp test test_split travis

