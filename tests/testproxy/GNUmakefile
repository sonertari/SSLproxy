TESTPROXY:= ~/.cargo/bin/testproxy

all: test

buildsslproxy:
	$(MAKE) -C ../../

buildlp:
	$(MAKE) -C lp

test: buildsslproxy buildlp
	sudo ./lp/lp -f ./lp/lp.conf -o Debug=no -o Daemon=yes -o User=nobody
	sudo ../../src/sslproxy -f sslproxy.conf -o Debug=no -o Daemon=yes -o User=nobody
	$(TESTPROXY) -f testharness.json
	sudo pkill sslproxy
	sudo pkill lp

travis: test

clean:
	$(MAKE) -C ../../ clean
	$(MAKE) -C lp clean

FORCE:

.PHONY: all clean buildsslproxy buildlp test travis

