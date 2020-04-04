TESTPROXY:= ~/.cargo/bin/testproxy

all: test

buildsslproxy:
	$(MAKE) -C ../../

buildlp:
	$(MAKE) -C lp

test: buildsslproxy buildlp
	sudo LD_LIBRARY_PATH=$(LD_LIBRARY_PATH) ./lp/lp -f ./lp/lp.conf -o Debug=no -o Daemon=yes -o User=nobody
ifeq ($(NO_TLS10),yes)
	sudo LD_LIBRARY_PATH=$(LD_LIBRARY_PATH) ../../src/sslproxy -f sslproxy_no_tls10.conf -o Debug=no -o Daemon=yes -o User=nobody
	$(TESTPROXY) -f testharness_no_tls10.json -l 4
else
ifeq ($(NO_TLS11),yes)
	sudo LD_LIBRARY_PATH=$(LD_LIBRARY_PATH) ../../src/sslproxy -f sslproxy_no_tls11.conf -o Debug=no -o Daemon=yes -o User=nobody
	$(TESTPROXY) -f testharness_no_tls11.json -l 4
else
	sudo LD_LIBRARY_PATH=$(LD_LIBRARY_PATH) ../../src/sslproxy -f sslproxy.conf -o Debug=no -o Daemon=yes -o User=nobody
	$(TESTPROXY) -f testharness.json -l 4
endif
endif
	sudo pkill sslproxy
	sudo pkill lp

travis: test

clean:
	$(MAKE) -C ../../ clean
	$(MAKE) -C lp clean

FORCE:

.PHONY: all clean buildsslproxy buildlp test travis

