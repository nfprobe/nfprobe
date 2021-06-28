# why use makefile while we alreay have cargo?

.PHONY: all
all: nfprobe bpf

.PHONY: nfprobe
nfprobe:
	cargo build

.PHONY: bpf
bpf:
	make -C bpf

.PHONY: clean
clean:
	cargo clean
	make -C bpf clean
