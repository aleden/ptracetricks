CXX := clang++

ARCH := arm

ptracetricks: ptracetricks.cpp
	@echo CXX $@
	$(CXX) -o $@ -std=gnu++14 -Wall -Ofast -I arch/$(ARCH) $< -static
