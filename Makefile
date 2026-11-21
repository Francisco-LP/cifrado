# Compila la CLI y los tests sin necesidad de CMake.
# Para la aplicación de escritorio (Qt 6) usa CMake; ver README.

CXX      ?= g++
CXXFLAGS ?= -std=c++17 -Wall -Wextra -O2
CPPFLAGS += -Icore
LIBS      = -lcrypto
BUILD     = build

CORE_OBJ  = $(BUILD)/core/cifrado.o

all: cifrado

cifrado: $(CORE_OBJ) $(BUILD)/cli/main.o
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LIBS)

$(BUILD)/cifrado_tests: $(CORE_OBJ) $(BUILD)/tests/test_core.o
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LIBS)

$(BUILD)/%.o: %.cpp core/cifrado.hpp
	@mkdir -p $(dir $@)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c $< -o $@

test: $(BUILD)/cifrado_tests
	./$(BUILD)/cifrado_tests

clean:
	rm -rf $(BUILD) cifrado

.PHONY: all test clean

# Paquetes (ver packaging/)
rpm:
	./packaging/rpm/build-rpm.sh

flatpak:
	./packaging/flatpak/build-flatpak.sh

.PHONY: rpm flatpak
