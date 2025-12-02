# Компилятор и флаги
CXX = g++
CXXFLAGS = -std=c++11 -Wall -O2

# Пути к Crypto++
CRYPTOPP_INCLUDE = -I/usr/include/cryptopp
CRYPTOPP_LIB = -lcryptopp

# Имя программы
TARGET = hash_sha1

# Основная цель
all: $(TARGET)

# Сборка программы
$(TARGET): hash_sha1.cpp
	$(CXX) $(CXXFLAGS) $(CRYPTOPP_INCLUDE) -o $@ $< $(CRYPTOPP_LIB)

# Тестирование
test: $(TARGET)
	@echo "=== Тестирование SHA-1 программы ==="
	@echo ""
	
	@echo "1. Тест SHA-1 с текстом 'program':"
	@echo -n "program" > test_file.txt
	@echo "   Файл: test_file.txt (содержит 'program')"
	@echo "   Результат:"
	@./$(TARGET) test_file.txt
	@echo "   Ожидаемый: 81d9aeea0e1a408d65b6660a176c5de83dc98e7b"
	@echo "   Проверка:  $$(sha1sum test_file.txt | cut -d' ' -f1)"
	@echo ""
	
	@echo "2. Тест SHA-1 с пустым файлом:"
	@touch empty.txt
	@echo "   Результат:"
	@./$(TARGET) empty.txt
	@echo "   Ожидаемый: da39a3ee5e6b4b0d3255bfef95601890afd80709"
	@echo ""
	
	@echo "3. Тест SHA-1 с фразой 'hello timp':"
	@echo -n "hello timp" > hello.txt
	@echo "   Результат:"
	@./$(TARGET) hello.txt
	@echo "   Ожидаемый: cbf8babc54944d22d632fdf92225aeca79fa2a05"
	@echo ""
	
	@rm -f test_file.txt empty.txt hello.txt
	@echo "=== Тестирование завершено ==="

# Быстрая проверка
quick-test: $(TARGET)
	@echo -n "test" > test.txt
	@echo "SHA-1 для файла с 'test':"
	@./$(TARGET) test.txt
	@echo "sha1sum для сравнения: $$(sha1sum test.txt | cut -d' ' -f1)"
	@rm -f test.txt

# Очистка
clean:
	rm -f $(TARGET) test_file.txt empty.txt hello.txt test.txt

.PHONY: all test quick-test clean
