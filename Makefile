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
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules
	$(shell find ./ -name "*.o" | xargs ~/bin/disasm.sh &>/dev/null)

modules: ccflags-y += ${PRODUCTION_CFLAGS}
modules: clean trim lint
modules:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd)
	$(shell find ./ -name "*.o" | xargs ~/bin/disasm.sh &>/dev/null)

# note, for centos kernels built from centos source, make sure that
# /usr/src/kernels/$(uname -r)/certs has the signing keys and associated files.
# e.g., sudo cp -v ~/src/linux/certs/* /usr/src/kernels/$(uname -r)/certs/
# also see https://www.kernel.org/doc/html/v4.15/admin-guide/module-signing.html

modules_install:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules_install

.PHONY: lint
lint:
	find . -name "*.c"  -exec cppcheck --force {} \;
	find . -name "*.h"  -exec cppcheck --force {} \;

.PHONY: trim
trim:
	$(shell find ./ -name "*.c" | xargs ~/bin/ttws.sh &>/dev/null)
	$(shell find ./ -name "*.h" | xargs ~/bin/ttws.sh &>/dev/null)
	$(shell find ./ -name "Makefile" | xargs ~/bin/ttws.sh &>/dev/null)

.PHONY: disassemble
disassemble:
	find ./ -name "*.o" | xargs ~/bin/disasm.sh
