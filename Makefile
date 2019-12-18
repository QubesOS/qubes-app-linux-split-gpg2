SHELL=/bin/bash

PYTHON ?= python3

.PHONY: build
build:
	$(PYTHON) setup.py build

clean:

install: install-python install-other

install-python:
	$(PYTHON) setup.py install -O1 $(PYTHON_PREFIX_ARG) --root $(DESTDIR)

install-other:
	install -d $(DESTDIR)/usr/share/split-gpg2 $(DESTDIR)/etc/qubes-rpc $(DESTDIR)/lib/systemd/system
	install -d $(DESTDIR)/usr/share/doc/split-gpg2
	install -d $(DESTDIR)/usr/share/doc/split-gpg2/examples
	install split-gpg2-client $(DESTDIR)/usr/share/split-gpg2/
	install -m 755 qubes.Gpg2.service $(DESTDIR)/etc/qubes-rpc/qubes.Gpg2
	install -m 644 split-gpg2-client.service $(DESTDIR)/lib/systemd/system/
	install -m 644 split-gpg2-rc.example $(DESTDIR)/usr/share/doc/split-gpg2/examples/
	install -m 644 README.md $(DESTDIR)/usr/share/doc/split-gpg2/
