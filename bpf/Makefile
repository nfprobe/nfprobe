MAKEFLAGS += --no-builtin-rules

ROOT_DIR:=$(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))

CLANG_FLAGS := -I$(ROOT_DIR)/include
CLANG_FLAGS += -target bpf -emit-llvm -O2 -g
CLANG_FLAGS += -Wall -Werror -Wno-format-security
LLC_FLAGS   := -march=bpf -mcpu=probe -mattr=dwarfris -filetype=obj

CLANG  ?= clang
LLC    ?= llc

BPF := nfprobe.o

.PHONY: all
all: $(BPF)

%.ll : %.c Makefile
	$(CLANG) $(CLANG_FLAGS) -c $*.c -o $*.ll
	$(CLANG) $(CLANG_FLAGS) -M $*.c > $*.d
	@cp -f $*.d $*.d.tmp
	@sed -e 's/.*://' -e 's/\\$$//' < $*.d.tmp | fmt -1 | \
	  sed -e 's/^ *//' -e 's/$$/:/' >> $*.d
	@rm -f $*.d.tmp

%.o : %.ll
	$(LLC) $(LLC_FLAGS) -o $@ $<

.PHONY: clean
clean:
	rm -f *.o *.d *.s

-include $(BPF:.o=.d)
