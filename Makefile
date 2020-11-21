CXX := clang++

ptracetricks: ptracetricks.cpp
	@echo CXX $@
	$(CXX) -o $@ -std=gnu++14 -Wall -O3 $< -static
