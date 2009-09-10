#Location of apxs command:
#APXS=apxs2
APXS=apxs

VERSION=0.0.2

TAR= CHANGES  INSTALL  Makefile  README  mod_authnz_certs.c

install: mod_authnz_certs.la
	$(APXS) -i -a mod_authnz_certs.la

build: mod_authnz_certs.la

mod_authnz_certs.la: 
	$(APXS) -c mod_authnz_certs.c

clean:
	rm -rf mod_authnz_certs.so mod_authnz_certs.o \
	    mod_authnz_certs.la mod_authnz_certs.slo \
	    mod_authnz_certs.lo .libs \
	    mod_authnz_certs-*.tar.gz


dist: $(TAR)
	tar zcvf mod_authnz_certs-$(VERSION).tar.gz $(TAR)
