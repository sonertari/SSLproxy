TESTPROXY:= ~/.cargo/bin/testproxy

all: test

buildsslproxy:
	$(MAKE) -C ../../

buildlp:
	$(MAKE) -C lp

test: buildsslproxy buildlp
	sudo ./lp/lp -f ./lp/lp.conf -o Debug=no -o Daemon=yes -o User=nobody
	sudo ../../src/sslproxy -f sslproxy.conf -o Debug=no -o Daemon=yes -o User=nobody
	# TODO: Install cargo first, in travis config before_install, using one of the following command lines
	#curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
	#curl https://sh.rustup.rs -sSf | sh
	#cargo install testproxy
	$(TESTPROXY) -f testharness.json
	sudo pkill sslproxy
	sudo pkill lp

clean:
	sudo pkill sslproxy
	sudo pkill lp
	$(MAKE) -C lp clean

FORCE:

.PHONY: all clean buildsslproxy buildlp test

