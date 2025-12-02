#include <iostream>
#include <string>
#include <cstring>

#include <cryptopp/cryptlib.h>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>
#include <cryptopp/filters.h>

using namespace CryptoPP;

int main(int argc, char* argv[]) {
    // Проверка аргументов
    if (argc != 2) {
        std::cout << "Программа вычисления SHA-1 хеш-суммы файлов" << std::endl;
        std::cout << "Использование: " << argv[0] << " <файл>" << std::endl;
        return 1;
    }
    
    std::string filename = argv[1];
    std::string digest;
    
    try {
        SHA1 hash;
        FileSource(filename.c_str(), true,
            new HashFilter(hash,
                new HexEncoder(
                    new StringSink(digest), false)));
        
        // Вывод результата
        std::cout << digest << std::endl;
        return 0;
        
    } catch (const CryptoPP::Exception& e) {
        std::cerr << "Ошибка Crypto++: " << e.what() << std::endl;
        return 1;
    } catch (const std::exception& e) {
        std::cerr << "Ошибка: " << e.what() << std::endl;
        return 1;
    }
}
