
# e.g.
# make ARCH=mips LLVM_CLANGXX=clang++-10 LLVM_CONFIG=llvm-config-10

ARCH         ?= unknown
LLVM_CLANGXX ?= clang++
LLVM_CONFIG  ?= llvm-config

CXXFLAGS  := -Ofast \
             -Wall \
             -Wno-initializer-overrides \
             -Wno-c99-designator \
             -std=gnu++14 \
             -I arch/$(ARCH)

CXXFLAGS += $(filter-out -fno-exceptions,$(shell $(LLVM_CONFIG) --cxxflags))

ptracetricks: ptracetricks.cpp
	@echo CXX $@
	$(LLVM_CLANGXX) -o $@ $(CXXFLAGS) $< -static
