BINDIR =	/usr/local/sbin
MANDIR =	/usr/local/man/man8
CC =		gcc
DEFINES =	
INCDIRS =	
LIBDIRS =	
CFLAGS =	-O $(DEFINES) $(INCDIRS)
LDFLAGS =	-s $(LIBDIRS)
INSTALL =	/usr/bin/install

all: milter-dnsbl

milter-dnsbl: milter-dnsbl.o
	$(CC) $(LDFLAGS) milter-dnsbl.o -lmilter -llwres -pthread -o milter-dnsbl

.c.o:
	$(CC) $(CFLAGS) -c $<

milter-dnsbl.o:	milter-dnsbl.c

install: install-bin install-man

install-bin: all
	$(INSTALL) -c milter-dnsbl $(BINDIR)/milter-dnsbl

install-man:
	$(INSTALL) -c -m 644 milter-dnsbl.8 $(MANDIR)/milter-dnsbl.8

clean:
	rm -f milter-dnsbl *.o a.out core
