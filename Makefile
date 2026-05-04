CXX     = g++
CXXFLAGS = -std=c++17 -Wall -O2
LIBS    = -lssl -lcrypto
TARGET  = cifrado
SRC     = cifrado.cpp

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) $(SRC) -o $(TARGET) $(LIBS)

clean:
	rm -f $(TARGET)