SHELL := /usr/bin/bash
MAKE := /usr/bin/make

INC_DIR := /usr/src/kernels/$(shell uname -r)/include
INC_PATH := -I. -I${INC_DIR}

MY_CFLAGS = -c  -Wall -Werror -std=gnu11 -fms-extensions -nostdlib
DEBUG_CFLAGS = -g -DDEBUG -fno-inline
PRODUCTION_CFLAGS = -f-inline -02
OBJECT_FILES_NON_STANDARD := ymake
ccflags-y := ${MY_CFLAGS} ${INC_PATH}
obj-m += cpu_hotplug.o

.PHONY: default
default: debug-modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) clean

super-clean: clean
	$(shell rm *.~*~ &>/dev/null)
	$(shell rm *.o.asm &>/dev/null)

debug-modules: ccflags-y += ${DEBUG_CFLAGS}
debug-modules: clean trim lint
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd)
	find ./ -name "*.o" | xargs ~/bin/disasm.sh &>/dev/null

modules: ccflags-y += ${PRODUCTION_CFLAGS}
modules: clean trim lint
modules:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd)
	find ./ -name "*.o" | xargs ./disasm.sh &>/dev/null

# note, for centos kernels built from centos source, make sure that
# /usr/src/kernels/$(uname -r)/certs has the signing keys and associated files.
# e.g., sudo cp -v ~/src/linux/certs/* /usr/src/kernels/$(uname -r)/certs/
# also see https://www.kernel.org/doc/html/v4.15/admin-guide/module-signing.html


modules_install: sign
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules_install

.PHONY: install
install: modules_install

.PHONY: run
run: modules_install
	modprobe cpu_hotplug
	lsmod | grep cpu_hotplug

.PHONY: unload
unload:
	rmmod cpu_hotplug
	dmesg

.PHONY: lint
lint:
	find . -name "*.c"  -exec cppcheck --force {} \;
	find . -name "*.h"  -exec cppcheck --force {} \;

.PHONY: trim
trim:
	find ./ -name "*.c" | xargs ./ttws.sh &>/dev/null
	find ./ -name "*.h" | xargs ./ttws.sh &>/dev/null
	find ./ -name "Makefile" | xargs ./ttws.sh &>/dev/null

.PHONY: disassemble
disassemble:
	find ./ -name "*.o" | xargs ./disasm.sh

.PHONY: sign
sign:
	/usr/src/kernels/$(shell uname -r)/scripts/sign-file sha512 \
	/usr/src/kernels/$(shell uname -r)/certs/signing_key.pem \
	/usr/src/kernels/$(shell uname -r)/certs/signing_key.x509 cpu_hotplug.ko
