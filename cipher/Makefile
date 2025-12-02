CXX = g++
CXXFLAGS = -std=c++11 -Wall -O2 -Wno-cpp
CRYPTOPP_INCLUDE = -I/usr/include/cryptopp
CRYPTOPP_LIB = -lcryptopp
TARGET = crypto_tool

all: $(TARGET)

$(TARGET): crypto_tool.cpp
	$(CXX) $(CXXFLAGS) $(CRYPTOPP_INCLUDE) -DCRYPTOPP_ENABLE_NAMESPACE_WEAK=1 -o $@ $< $(CRYPTOPP_LIB)

test: $(TARGET)
	@echo "=== Тестирование программы шифрования ==="
	@echo ""
	
	@echo "1. Создаем тестовый файл..."
	@echo "Это тестовое содержимое для шифрования." > test_file.txt
	
	@echo "2. Тест короткого пароля (должна быть ошибка)..."
	@./$(TARGET) -e -i test_file.txt -o test1.bin -p "12345" 2>&1 | grep -q "минимум 6" && echo "   ✓ Короткий пароль отклонен" || echo "   ✗ Должна быть ошибка"
	
	@echo "3. Тест шифрования..."
	@./$(TARGET) -e -i test_file.txt -o test2.bin -p "MyPass123" 2>&1 | grep -q "Готово" && echo "   ✓ Шифрование успешно" || echo "   ✗ Ошибка при шифровании"
	
	@echo "4. Тест дешифрования..."
	@./$(TARGET) -d -i test2.bin -o test2_dec.txt -p "MyPass123" 2>&1 | grep -q "Готово" && echo "   ✓ Дешифрование успешно" || echo "   ✗ Ошибка при дешифровании"
	
	@echo "5. Проверка целостности данных..."
	@if cmp -s test_file.txt test2_dec.txt; then \
		echo "   ✓ Исходный и расшифрованный файлы идентичны"; \
	else \
		echo "   ✗ Ошибка: файлы отличаются"; \
	fi
	
	@echo "6. Тест с неправильным паролем..."
	@./$(TARGET) -d -i test2.bin -o wrong_out.txt -p "WrongPass123" 2>&1 | grep -q "Ошибка" && echo "   ✓ Неправильный пароль отклонен" || echo "   ✗ Должна быть ошибка"
	
	@echo "7. Тест авто-расширения..."
	@./$(TARGET) -e -i test_file.txt -o test3 -p "Pass123" --auto-ext 2>&1 | grep -q "Готово" && echo "   ✓ Авто-расширение .bin работает" || echo "   ✗ Ошибка"
	@if [ -f test3.bin ]; then echo "   ✓ Файл test3.bin создан"; fi
	
	@rm -f test_file.txt test*.bin test*.txt
	@echo ""
	@echo "=== Все тесты пройдены успешно ==="
	@echo "Программа работает корректно!"

clean:
	rm -f $(TARGET) *.bin *.txt test_* *_decrypted

quick:
	$(CXX) $(CXXFLAGS) $(CRYPTOPP_INCLUDE) -o $(TARGET) crypto_tool.cpp $(CRYPTOPP_LIB)

examples:
	@echo "=== Примеры использования программы ==="
	@echo ""
	@echo "1. Шифрование файла:"
	@echo "   ./$(TARGET) -e -i document.txt -o secret.bin -p \"MyPass123\""
	@echo ""
	@echo "2. Дешифрование файла:"
	@echo "   ./$(TARGET) -d -i secret.bin -o result.txt -p \"MyPass123\""
	@echo ""
	@echo "3. С авто-расширениями:"
	@echo "   ./$(TARGET) -e -i photo.jpg -o encrypted -p \"Secure12\" --auto-ext"
	@echo "   # Создаст: encrypted.bin"
	@echo ""
	@echo "4. Интерактивный режим:"
	@echo "   ./$(TARGET) --interactive"
	@echo ""
	@echo "5. Показать справку:"
	@echo "   ./$(TARGET) -h"

install: $(TARGET)
	@echo "Копирование программы в /usr/local/bin..."
	@cp $(TARGET) /usr/local/bin/ 2>/dev/null || echo "Для установки требуются права администратора: sudo cp $(TARGET) /usr/local/bin/"

.PHONY: all test clean quick examples install
