CXX := clang++

ARCH := arm

CFLAGS := -Ofast \
          -Wall \
          -Wno-initializer-overrides \
          -Wno-c99-designator \
          -std=gnu++14 \
          -I arch/$(ARCH)

ptracetricks: ptracetricks.cpp
	@echo CXX $@
	$(CXX) -o $@ $(CFLAGS) $< -static
