CXX := g++
CXXFLAGS := $(shell llvm-config --cxxflags)
LDFLAGS := $(shell llvm-config --ldflags)
LIBS := $(shell llvm-config --libs object core support) -ldl -lpthread -lncurses
STRIP := strip

all: arm-unwind-dump

arm-unwind-dump: arm-unwind-dump.cpp
	$(CXX) -o $@ $< $(CXXFLAGS) $(LDFLAGS) $(LIBS)
	$(STRIP) $@

.PHONY: clean
clean:
	-rm arm-unwind-dump
