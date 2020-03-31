SRCDIR:=	    src
CHECKTESTSDIR:=	    tests/check
TESTPROXYTESTSDIR:= tests/testproxy

TARGET:=	sslproxy

all: $(TARGET)

$(TARGET):
	$(MAKE) -C $(SRCDIR)

test: $(TARGET)
	$(MAKE) -C $(CHECKTESTSDIR)
	$(MAKE) -C $(TESTPROXYTESTSDIR)

clean:
	$(MAKE) -C $(SRCDIR) clean
	$(MAKE) -C $(CHECKTESTSDIR) clean

travis: $(TARGET)
	$(MAKE) -C $(CHECKTESTSDIR) travis
	$(MAKE) -C $(TESTPROXYTESTSDIR) travis

install:
	$(MAKE) -C $(SRCDIR) install

deinstall:
	$(MAKE) -C $(SRCDIR) deinstall

lint:
	$(MAKE) -C $(SRCDIR) lint

manlint:
	$(MAKE) -C $(SRCDIR) manlint

mantest:
	$(MAKE) -C $(SRCDIR) mantest

copyright: *.c *.h *.1 *.5 extra/*/*.c
	Mk/bin/copyright.py $^

man:
	$(MAKE) -C $(SRCDIR) man

manclean:
	$(MAKE) -C $(SRCDIR) manclean

fetchdeps:
	$(WGET) -O- $(KHASH_URL) >$(SRCDIR)/khash.h
	#$(RM) -rf xnu/xnu-*
	$(MAKE) -C xnu fetch

dist:
	$(MAKE) -C $(SRCDIR) dist

disttest:
	$(MAKE) -C $(SRCDIR) disttest

distclean:
	$(MAKE) -C $(SRCDIR) distclean

realclean:
	$(MAKE) -C $(SRCDIR) realclean
	$(MAKE) -C $(CHECKTESTSDIR) realclean
FORCE:

.PHONY: all config clean buildtest test sudotest travis lint \
        install deinstall copyright manlint mantest man manclean fetchdeps \
        dist disttest distclean realclean

