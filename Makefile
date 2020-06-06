#! /usr/bin/make

OBJ_DIR := build

SRC := $(wildcard *.cpp)
OBJECTS  := $(SRC:%.cpp=$(OBJ_DIR)/%.o)
EXEC := $(OBJ_DIR)/exec

CXXFLAGS := -g

$(OBJ_DIR)/%.o : %.cpp
	@mkdir -p $(@D)
	g++ $(CXXFLAGS) $(INCLUDE) -c $< -o $@ $(LDFLAGS)


$(EXEC) : $(OBJECTS)
	g++ -o $@ $(OBJECTS) $(LDFLAGS)

clean:
	rm -rf $(OBJ_DIR)/*

build: $(EXEC)

run : $(EXEC)
	./${EXEC}

.PHONY : build clean run


