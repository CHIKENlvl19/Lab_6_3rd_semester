# Компилятор
CXX = g++
CXXFLAGS = -Wall -Wextra -std=c++17 -Iinclude

# Библиотеки
LIBS = -lpq

# Файлы
SRC = src/main.cpp src/db.cpp
OBJ = $(SRC:.cpp=.o)

# Имя бинарника
TARGET = vuln_db

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CXX) $(OBJ) -o $(TARGET) $(LIBS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) $(TARGET)

rebuild: clean all
