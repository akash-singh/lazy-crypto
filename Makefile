#! /usr/bin/make

OBJ_DIR := build

SRC := $(wildcard *.cpp)
OBJECTS  := $(SRC:%.cpp=$(OBJ_DIR)/%.o)
EXEC := $(OBJ_DIR)/exec
INCLUDE = -I yaml-cpp/include
LDFLAGS = -L yaml-cpp/build -l yaml-cpp

CXXFLAGS := -g

$(OBJ_DIR)/%.o : %.cpp
	@mkdir -p $(@D)
	g++ $(CXXFLAGS) $(INCLUDE) -c $< -o $@

$(EXEC) : $(OBJECTS)
	g++ -o $@ $(OBJECTS) $(LDFLAGS)

clean:
	rm -rf $(OBJ_DIR)/*

build: $(EXEC)

test: build test_vectors.yml
	./build/exec

test_vectors.yml : 
	./gen_test_vectors.py 1

run : $(EXEC)
	./${EXEC}

.PHONY : build test clean run


