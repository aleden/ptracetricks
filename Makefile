
# e.g.
# make ARCH=mips LLVM_CLANGXX=clang++-10 LLVM_CONFIG=llvm-config-10

ARCH         ?= unknown
LLVM_CLANGXX ?= clang++
LLVM_CONFIG  ?= llvm-config

CXXFLAGS  := -Ofast \
             -Wall \
             -Wno-initializer-overrides \
             -Wno-c99-designator \
             -I arch/$(ARCH)

CXXFLAGS += $(filter-out -fno-exceptions,$(shell $(LLVM_CONFIG) --cxxflags))

CXXFLAGS += -std=gnu++17

LLVM_COMPONENTS := core \
                   native

LDFLAGS := $(shell $(LLVM_CONFIG) --ldflags)
LDFLAGS += $(shell $(LLVM_CONFIG) --link-static --libs $(LLVM_COMPONENTS))
LDFLAGS += $(shell $(LLVM_CONFIG) --link-static --system-libs)
LDFLAGS += -latomic

ptracetricks: ptracetricks.cpp
	@echo CXX $@
	$(LLVM_CLANGXX) -o $@ $(CXXFLAGS) $< $(LDFLAGS)
