# 046267 Computer Architecture - Winter 23.22 - HW #2

CC = g++

CFLAGS = -g -Wall
LDFLAGS = 
TARGET = cacheSim
SOURCES = $(TARGET).cpp
OBJECTS = $(SOURCES:.cpp = .o)

all: $(TARGET)

$(TARGET) : $(OBJECTS)
		$(CC) $(LDFLAGS) $(OBJECTS) -o $@ 


.cpp.o:
	$(CC) $(CLFAGS) $< -o $@ 

.PHONY: clean
clean:
	rm -f *.o
	rm -f cacheSim
