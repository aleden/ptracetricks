
# e.g.
# make ARCH=mips LLVM_CLANGXX=clang++-10 LLVM_CONFIG=llvm-config-10

ARCH         ?= unknown
LLVM_CLANGXX ?= clang++
LLVM_CONFIG  ?= llvm-config

CXXFLAGS  := -Ofast \
             -g \
             -Wall \
             -Wno-initializer-overrides \
             -Wno-c99-designator \
             -I arch/$(ARCH)

#CXXFLAGS += $(filter-out -fno-exceptions,$(shell $(LLVM_CONFIG) --cxxflags))

CXXFLAGS += -fexceptions
CXXFLAGS += -std=gnu++17

ifeq "$(ARCH)" "arm"
#LLVM_COMPONENTS := armdisassembler
LLVM_COMPONENTS := core native
else
LLVM_COMPONENTS := core native
endif

#LDFLAGS := $(shell $(LLVM_CONFIG) --ldflags)
#LDFLAGS += $(shell $(LLVM_CONFIG) --link-static --libs $(LLVM_COMPONENTS))
#LDFLAGS += $(shell $(LLVM_CONFIG) --link-static --system-libs)
#LDFLAGS += -pthread
#LDFLAGS += -ltinfo
#LDFLAGS += -lz
LDFLAGS += -latomic

VER := $(shell git log -n1 --format="%h")

ptracetricks.stripped: ptracetricks
	strip -o $@ $<

ptracetricks: ptracetricks.cpp
	@echo CXX $@
	$(LLVM_CLANGXX) -o $@ $(CXXFLAGS) -D PTRACETRICKS_VERSION=\"$(VER)\" $< -static -fPIC $(LDFLAGS)

.PHONY: clean
clean:
	rm -f ptracetricks ptracetricks.stripped
