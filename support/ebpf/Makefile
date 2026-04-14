SHELL ?= bash
BPF_CLANG ?= clang-17
BPF_LINK ?= llvm-link-17
STRIP ?= llvm-strip-17
LLC ?= llc-17
CLANG_FORMAT ?= clang-format-17

# Detect native architecture and translate to GOARCH.
NATIVE_ARCH := $(shell uname -m)
ifeq ($(NATIVE_ARCH),x86_64)
NATIVE_ARCH := amd64
else ifneq (,$(filter $(NATIVE_ARCH),aarch64 arm64))
NATIVE_ARCH := arm64
else
$(error Unsupported architecture: $(NATIVE_ARCH))
endif

# Use a placeholder like '.' or '/' as the new prefix.
REPRODUCIBLE_PREFIX := .

# Valid values: amd64, arm64.
TARGET_ARCH ?= $(NATIVE_ARCH)

TRACER_NAME ?= tracer.ebpf.$(TARGET_ARCH)

ifeq ($(TARGET_ARCH),arm64)
TARGET_FLAGS = -target aarch64-linux-gnu
else
TARGET_FLAGS = -target x86_64-linux-gnu
endif

# Resolve the paths to external BPF header directories via the Go module
# cache (honors any `replace` directive in go.mod). Headers live in their
# canonical upstream repos as the single source of truth and are not
# duplicated here:
#   * github.com/parca-dev/usdt      -> usdt_defs.h, usdt_args.h
#   * github.com/parca-dev/parcagpu  -> cupti_bpf.h
#
# Lazy assignment (`=`, not `:=`): only computed when an actual compile
# rule expands FLAGS, so `clean`/`format`/`lint` don't trigger it. We
# `go mod download` first because `go list -m -f '{{.Dir}}'` does not
# auto-download a specific module path on a cold cache.
USDT_HEADERS = $(shell cd $(CURDIR)/../.. && \
	go mod download github.com/parca-dev/usdt >/dev/null && \
	go list -m -f '{{.Dir}}' github.com/parca-dev/usdt)/ebpf

# parcagpu has no Go packages (only C headers), so it cannot live in go.mod
# (go mod tidy would remove it).  Use `go mod download -json @latest` which
# works for arbitrary modules without requiring a go.mod entry.
CUPTI_HEADERS = $(shell cd $(CURDIR)/../.. && \
	go mod download -json github.com/parca-dev/parcagpu@latest 2>/dev/null | \
	sed -n 's/.*"Dir": "\(.*\)".*/\1/p')/ebpf

# Use -g to generate the btf section in the resulting binary.
#
# We remap source roots to stable strings so the compiled .o (and the
# linked tracer.ebpf.* blob, since BTF/.BTF.ext survive `--strip-debug`)
# are byte-identical regardless of where the build happens:
#   * $(CURDIR)         — this directory (support/ebpf), already remapped.
#   * $(USDT_HEADERS)   — parca-dev/usdt module's ebpf/ headers, in the Go
#                         module cache (different absolute path locally
#                         vs. in CI).
#   * $(CUPTI_HEADERS)  — parca-dev/parcagpu module's ebpf/ headers, same
#                         reproducibility concern as USDT_HEADERS.
# Without these remaps, absolute paths get baked into BTF and the blob
# diffs across machines.
FLAGS=$(TARGET_FLAGS) -g \
	-fno-jump-tables \
	-nostdlib \
	-nostdinc \
	-ffreestanding \
	-O2 -emit-llvm -c $< \
	-I$(USDT_HEADERS) \
	-I$(CUPTI_HEADERS) \
	-Wall -Wextra -Werror \
	-Wno-address-of-packed-member \
	-Wno-unused-label \
	-Wno-sign-compare \
	-fno-stack-protector \
	-D__SOURCE_DATE_EPOCH__=0 \
	-std=gnu17 \
	-Xclang -fdebug-prefix-map=$(CURDIR)=$(REPRODUCIBLE_PREFIX) \
	-Xclang -fmacro-prefix-map=$(CURDIR)=$(REPRODUCIBLE_PREFIX) \
	-Xclang -fdebug-prefix-map=$(USDT_HEADERS)=usdt \
	-Xclang -fmacro-prefix-map=$(USDT_HEADERS)=usdt \
	-Xclang -fdebug-prefix-map=$(CUPTI_HEADERS)=cupti \
	-Xclang -fmacro-prefix-map=$(CUPTI_HEADERS)=cupti

SRCS := $(wildcard *.ebpf.c)
OBJS := $(SRCS:.c=.$(TARGET_ARCH).o)
DEPS := $(OBJS:.o=.d)

.DEFAULT_GOAL := all

all: $(TRACER_NAME)

amd64:
	$(MAKE) TARGET_ARCH=amd64

arm64:
	$(MAKE) TARGET_ARCH=arm64

errors.h: ../../tools/errors-codegen/errors.json
	go run ../../tools/errors-codegen/main.go bpf $@

%.ebpf.$(TARGET_ARCH).o: %.ebpf.c errors.h
	$(BPF_CLANG) $(FLAGS) -MMD -MP -o $@

$(TRACER_NAME): $(OBJS)
	$(BPF_LINK) $^ -o - | $(LLC) -march=bpf -mcpu=v2 -filetype=obj -o $@
	# With the compile flag -g not only the btf section is added to the
	# binary but also additional debug sections. As these debug sections
	# are not relevant for BPF and increase the binary size remove them here.
	$(STRIP) --strip-debug --enable-deterministic-archives $@
	@./print_instruction_count.sh $@

baseline: $(TRACER_NAME)
	cp $< $(TRACER_NAME).$@

bloatcheck: $(TRACER_NAME)
	python3 bloat-o-meter $(TRACER_NAME).baseline $(TRACER_NAME)

lint:
	$(CLANG_FORMAT) -Werror --dry-run -style=file *.[ch] ../../tools/coredump/*.[ch]

format:
	$(CLANG_FORMAT) -i -style=file *.[ch]

clean:
	rm -f *.o *.d

-include $(DEPS)
