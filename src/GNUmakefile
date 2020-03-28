SRCS:=	$(wildcard *.c)
HDRS:=	$(wildcard *.h)
OBJS:=	$(SRCS:.c=.o)
MKFS:=	$(wildcard GNUmakefile ../GNUmakefile ../Mk/*.mk)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

build.o: CPPFLAGS+=$(BUILD_CPPFLAGS)
build.o: build.c FORCE

%.o: %.c $(HDRS) $(MKFS)
	$(CC) -c $(CPPFLAGS) $(CFLAGS) -o $@ $<

clean:
	$(RM) -f $(TARGET) *.o .*.o *.core *~
	$(RM) -rf *.dSYM

install: $(TARGET)
	test -d $(DESTDIR)$(PREFIX)/bin || $(MKDIR) -p $(DESTDIR)$(PREFIX)/bin
	test -d $(DESTDIR)$(PREFIX)/$(MANDIR)/man1 || \
		$(MKDIR) -p $(DESTDIR)$(PREFIX)/$(MANDIR)/man1
	test -d $(DESTDIR)$(PREFIX)/$(MANDIR)/man5 || \
		$(MKDIR) -p $(DESTDIR)$(PREFIX)/$(MANDIR)/man5
	test -d $(DESTDIR)$(PREFIX)/$(EXAMPLESDIR)/$(TARGET) || \
		$(MKDIR) -p $(DESTDIR)$(PREFIX)/$(EXAMPLESDIR)/$(TARGET)
	$(INSTALL) $(BINOWNERFLAGS) -m $(BINMODE) \
		$(TARGET) $(DESTDIR)$(PREFIX)/bin/
	$(INSTALL) $(MANOWNERFLAGS) -m $(MANMODE) \
		$(TARGET).1 $(DESTDIR)$(PREFIX)/$(MANDIR)/man1/
	$(INSTALL) $(MANOWNERFLAGS) -m $(MANMODE) \
		$(TARGET).conf.5 $(DESTDIR)$(PREFIX)/$(MANDIR)/man5/
	$(INSTALL) $(MANOWNERFLAGS) -m $(EXAMPLESMODE) \
		$(TARGET).conf $(DESTDIR)$(PREFIX)/$(EXAMPLESDIR)/$(TARGET)/

deinstall:
	$(RM) -f $(DESTDIR)$(PREFIX)/bin/$(TARGET) $(DESTDIR)$(PREFIX)/$(MANDIR)/man1/$(TARGET).1 \
		$(DESTDIR)$(PREFIX)/$(MANDIR)/man5/$(TARGET).conf.5
	$(RM) -rf $(DESTDIR)$(PREFIX)/$(EXAMPLESDIR)/$(TARGET)/

ifdef GITDIR
lint:
	$(CPPCHECK) $(CPPCHECKFLAGS) --force --enable=all --error-exitcode=1 .

manlint: $(TARGET).1 $(TARGET).conf.5
	$(CHECKNR) $(TARGET).1

mantest: $(TARGET).1 $(TARGET).conf.5
	$(RM) -f man1 man5
	$(LN) -sf . man1
	$(LN) -sf . man5
	$(MAN) -M . 1 $(TARGET)
	$(MAN) -M . 5 $(TARGET).conf
	$(RM) man1 man5

$(PKGNAME)-$(VERSION).1.txt: $(TARGET).1
	$(RM) -f man1
	$(LN) -sf . man1
	$(MAN) -M . 1 $(TARGET) | $(COL) -b >$@
	$(RM) man1

$(PKGNAME)-$(VERSION).conf.5.txt: $(TARGET).conf.5
	$(RM) -f man5
	$(LN) -sf . man5
	$(MAN) -M . 5 $(TARGET).conf | $(COL) -b >$@
	$(RM) man5

man: $(PKGNAME)-$(VERSION).1.txt $(PKGNAME)-$(VERSION).conf.5.txt

manclean:
	$(RM) -f $(PKGNAME)-*.1.txt $(PKGNAME)-*.conf.5.txt

fetchdeps:
	$(WGET) -O- $(KHASH_URL) >khash.h
	#$(RM) -rf xnu/xnu-*
	$(MAKE) -C xnu fetch

dist: $(PKGNAME)-$(VERSION).tar.gz $(PKGNAME)-$(VERSION).tar.gz.asc

%.asc: %
	$(GPG) -u $(GPGSIGNKEY) --armor --output $@ --detach-sig $<

$(PKGNAME)-$(VERSION).tar.gz:
	$(MKDIR) -p $(PKGNAME)-$(VERSION)
	echo $(VERSION) >$(PKGNAME)-$(VERSION)/VERSION
	$(OPENSSL) dgst -sha1 -r *.[hc] | $(SORT) -k 2 \
		>$(PKGNAME)-$(VERSION)/HASHES
	# XXX: cd .. and >$(SRCDIR)/
	cd .. && $(GIT) archive --prefix=$(PKGNAME)-$(VERSION)/ HEAD \
		>$(SRCDIR)/$(PKGNAME)-$(VERSION).tar
	$(TAR) -f $(PKGNAME)-$(VERSION).tar -r $(PKGNAME)-$(VERSION)/VERSION
	$(TAR) -f $(PKGNAME)-$(VERSION).tar -r $(PKGNAME)-$(VERSION)/HASHES
	$(ZIP) <$(PKGNAME)-$(VERSION).tar >$(PKGNAME)-$(VERSION).tar.gz
	$(RM) $(PKGNAME)-$(VERSION).tar
	$(RM) -r $(PKGNAME)-$(VERSION)

disttest: $(PKGNAME)-$(VERSION).tar.gz $(PKGNAME)-$(VERSION).tar.gz.asc
	$(GPG) --verify $<.asc $<
	$(ZIP) -d < $< | $(TAR) -x -f -
	cd $(PKGNAME)-$(VERSION) && $(MAKE) && $(MAKE) test && ./$(SRCDIR)/$(TARGET) -V
	$(RM) -r $(PKGNAME)-$(VERSION)

distclean:
	$(RM) -f $(PKGNAME)-*.tar.gz*

realclean: distclean manclean clean

endif

FORCE:

.PHONY: all config clean lint \
        install deinstall manlint mantest man manclean fetchdeps \
        dist disttest distclean realclean

