SRCS:=	    $(wildcard *.t.c)
OBJS:=	    $(SRCS:.t.c=.t.o)

SRCSRCS:=   $(wildcard ../../$(SRCDIR)/*.c)
SRCHDRS:=   $(wildcard ../../$(SRCDIR)/*.h)
SRCSOBJS:=  $(SRCSRCS:.c=.o)
OBJS+=	    $(filter-out ../../$(SRCDIR)/main.o,$(SRCSOBJS))
MKFS:=	    $(wildcard GNUmakefile ../../$(SRCDIR)/GNUmakefile ../../GNUmakefile ../../Mk/*.mk)

all: test

$(TARGET).test: $(OBJS)
	$(CC) $(LDFLAGS) $(TPKG_LDFLAGS) -o $@ $^ $(LIBS) $(TPKG_LIBS)

%.t.o: %.t.c $(SRCHDRS) $(MKFS)
ifdef CHECK_MISSING
	$(error unit test dependency 'check' not found; \
	install it or point CHECK_BASE to base path)
endif
	$(CC) -c $(CPPFLAGS) $(TCPPFLAGS) $(CFLAGS) $(TPKG_CFLAGS) -o $@ \
		-x c $<

buildtest: TCPPFLAGS+=-D"TEST_ZEROUSR=\"$(shell id -u -n root||echo 0)\""
buildtest: TCPPFLAGS+=-D"TEST_ZEROGRP=\"$(shell id -g -n root||echo 0)\""
buildtest: TCPPFLAGS+=-I../../$(SRCDIR)
buildtest: $(TARGET).test
	$(MAKE) -C engine
	$(MAKE) -C pki testreqs

test: buildtest
	./$(TARGET).test

sudotest: buildtest
	sudo ./$(TARGET).test

travis: test

clean:
	$(MAKE) -C engine clean
	$(RM) -f $(TARGET).test *.o .*.o *.core *~
	$(RM) -rf *.dSYM

ifdef GITDIR
lint:
	$(CPPCHECK) $(CPPCHECKFLAGS) --force --enable=all --error-exitcode=1 .

realclean: clean
	$(MAKE) -C pki clean
endif

FORCE:

.PHONY: all config clean buildtest test sudotest travis realclean

