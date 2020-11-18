CXX := clang++-6.0

ptracetricks: ptracetricks.cpp
	@echo CXX $@
	$(CXX) -o $@ -std=gnu++14 -Wall -O3 $<
