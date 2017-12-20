# Makefile for SEAL examples
BIN_DIR=../bin
LIB_DIR=../bin
INCLUDE_DIR=../SEAL/
SRCS=main.cpp
SEALRUN=$(BIN_DIR)/sealexamples
CXX=g++-6
CXXFLAGS=-march=native -O3 -std=c++11 -pthread
LDFLAGS=

.PHONY : all clean

all : $(SEALRUN)

$(SEALRUN) : $(SRCS)
	@-mkdir -p $(dir $@)
	$(CXX) $(SRCS) $(CXXFLAGS) $(LDFLAGS) $(addprefix -I,$(INCLUDE_DIR)) $(addprefix -L,$(LIB_DIR)) -L$(HOME)/MyLib/lib -I$(HOME)/MyLib/include -lntl -lgmp -lseal -o $@

clean :
	@-rm -f $(OBJS) $(SEALRUN)
