#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <algorithm>
#include <cstring>
#include <stdexcept>

#include <cryptopp/cryptlib.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/files.h>
#include <cryptopp/sha.h>
#include <cryptopp/pwdbased.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>

using namespace CryptoPP;

std::string ensureBinExtension(const std::string& filename) {
    if (filename.length() >= 4 && 
        filename.substr(filename.length() - 4) == ".bin") {
        return filename;
    }
    
    size_t dotPos = filename.find_last_of('.');
    if (dotPos != std::string::npos) {
        return filename.substr(0, dotPos) + ".bin";
    }
    
    return filename + ".bin";
}

std::string removeBinExtension(const std::string& filename) {
    if (filename.length() >= 4 && 
        filename.substr(filename.length() - 4) == ".bin") {
        return filename.substr(0, filename.length() - 4);
    }
    return filename;
}

// Генерирует имя для расшифрованного файла
std::string generateDecryptedName(const std::string& encryptedFile) {
    std::string baseName = removeBinExtension(encryptedFile);
    
    // Если исходный файл уже заканчивается на _decrypted, оставляем как есть
    if (baseName.length() >= 10 && 
        baseName.substr(baseName.length() - 10) == "_decrypted") {
        return baseName;
    }
    
    // Добавляем _decrypted
    return baseName + "_decrypted";
}

bool hasBinExtension(const std::string& filename) {
    return filename.length() >= 4 && 
           filename.substr(filename.length() - 4) == ".bin";
}

class CryptoProcessor {
public:
    // Режимы работы
    enum Mode {
        ENCRYPT,
        DECRYPT
    };
    
    // Конструктор
    CryptoProcessor() = default;
    
    // Основной метод для шифрования/дешифрования
    void processFile(Mode mode, 
                     const std::string& inputFile,
                     const std::string& outputFile,
                     const std::string& password);
    
    // Получение информации об алгоритме
    std::string getAlgorithmInfo() const;
    
private:
    // Параметры алгоритма AES-256
    struct AlgorithmParams {
        size_t keySize = 32;     // 256 бит
        size_t blockSize = 16;   // 128 бит
        std::string name = "AES-256 (CBC)";
    };
    
    // Вспомогательные методы
    std::vector<unsigned char> deriveKey(const std::string& password, size_t keySize);
    std::vector<unsigned char> generateIV(size_t blockSize);
    std::vector<unsigned char> readFile(const std::string& filename);
    void writeFile(const std::string& filename, const std::vector<unsigned char>& data);
    void validatePassword(const std::string& password);
    AlgorithmParams getAlgorithmParams() const;
    
    // Основной метод обработки AES
    void processAES(Mode mode, const std::string& inputFile, 
                    const std::string& outputFile, const std::string& password);
};

// Реализация методов CryptoProcessor
std::string CryptoProcessor::getAlgorithmInfo() const {
    auto params = getAlgorithmParams();
    return params.name + " (Key: " + std::to_string(params.keySize * 8) + 
           " bits, Block: " + std::to_string(params.blockSize * 8) + " bits)";
}

CryptoProcessor::AlgorithmParams CryptoProcessor::getAlgorithmParams() const {
    return AlgorithmParams();
}

std::vector<unsigned char> CryptoProcessor::deriveKey(const std::string& password, size_t keySize) {
    try {
        std::vector<unsigned char> key(keySize);
        
        // Используем PBKDF2 для генерации ключа из пароля
        byte salt[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
        
        PKCS5_PBKDF2_HMAC<SHA256> pbkdf;
        pbkdf.DeriveKey(key.data(), key.size(), 0,
                       reinterpret_cast<const byte*>(password.data()), password.size(),
                       salt, sizeof(salt), 10000);
        
        return key;
    } catch (const CryptoPP::Exception& e) {
        throw std::runtime_error("Ошибка генерации ключа: " + std::string(e.what()));
    }
}

std::vector<unsigned char> CryptoProcessor::generateIV(size_t blockSize) {
    try {
        std::vector<unsigned char> iv(blockSize);
        AutoSeededRandomPool prng;
        prng.GenerateBlock(iv.data(), iv.size());
        return iv;
    } catch (const CryptoPP::Exception& e) {
        throw std::runtime_error("Ошибка генерации IV: " + std::string(e.what()));
    }
}

std::vector<unsigned char> CryptoProcessor::readFile(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Не удалось открыть файл: " + filename);
    }
    
    file.seekg(0, std::ios::end);
    size_t size = file.tellg();
    file.seekg(0, std::ios::beg);
    
    std::vector<unsigned char> buffer(size);
    file.read(reinterpret_cast<char*>(buffer.data()), size);
    
    return buffer;
}

void CryptoProcessor::writeFile(const std::string& filename, const std::vector<unsigned char>& data) {
    std::ofstream file(filename, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Не удалось создать файл: " + filename);
    }
    
    file.write(reinterpret_cast<const char*>(data.data()), data.size());
}

void CryptoProcessor::validatePassword(const std::string& password) {
    if (password.empty()) {
        throw std::runtime_error("Пароль не может быть пустым");
    }
    if (password.length() < 6) {
        throw std::runtime_error("Пароль должен содержать минимум 6 символов");
    }
}

void CryptoProcessor::processFile(Mode mode, 
                                 const std::string& inputFile,
                                 const std::string& outputFile,
                                 const std::string& password) {
    
    // Проверка пароля
    validatePassword(password);
    
    // Выполнение операции шифрования/дешифрования AES
    processAES(mode, inputFile, outputFile, password);
}

void CryptoProcessor::processAES(Mode mode, const std::string& inputFile, 
                                const std::string& outputFile, const std::string& password) {
    try {
        // Параметры AES-256
        auto params = getAlgorithmParams();
        const size_t KEY_SIZE = params.keySize;
        const size_t BLOCK_SIZE = params.blockSize;
        
        // Генерация ключа из пароля
        auto key = deriveKey(password, KEY_SIZE);
        
        if (mode == ENCRYPT) {
            // Генерация IV
            auto iv = generateIV(BLOCK_SIZE);
            
            // Чтение исходных данных
            auto plaintext = readFile(inputFile);
            
            // Шифрование
            CBC_Mode<CryptoPP::AES>::Encryption encryptor;
            encryptor.SetKeyWithIV(key.data(), key.size(), iv.data());
            
            std::string ciphertext;
            StringSource ss(plaintext.data(), plaintext.size(), true,
                new StreamTransformationFilter(encryptor,
                    new StringSink(ciphertext)));
            
            // Запись результата (IV + зашифрованные данные)
            std::vector<unsigned char> result;
            result.reserve(iv.size() + ciphertext.size());
            result.insert(result.end(), iv.begin(), iv.end());
            result.insert(result.end(), ciphertext.begin(), ciphertext.end());
            
            writeFile(outputFile, result);
            
        } else { // DECRYPT
            // Чтение зашифрованных данных
            auto ciphertext = readFile(inputFile);
            
            if (ciphertext.size() < BLOCK_SIZE) {
                throw std::runtime_error("Файл слишком мал для содержания IV");
            }
            
            // Извлечение IV
            std::vector<unsigned char> iv(ciphertext.begin(), ciphertext.begin() + BLOCK_SIZE);
            std::vector<unsigned char> encryptedData(ciphertext.begin() + BLOCK_SIZE, ciphertext.end());
            
            // Дешифрование
            CBC_Mode<CryptoPP::AES>::Decryption decryptor;
            decryptor.SetKeyWithIV(key.data(), key.size(), iv.data());
            
            std::string decrypted;
            StringSource ss(encryptedData.data(), encryptedData.size(), true,
                new StreamTransformationFilter(decryptor,
                    new StringSink(decrypted)));
            
            // Запись результата
            writeFile(outputFile, std::vector<unsigned char>(decrypted.begin(), decrypted.end()));
        }
        
    } catch (const CryptoPP::Exception& e) {
        throw std::runtime_error("Ошибка AES: " + std::string(e.what()));
    }
}

// ==================== ФУНКЦИИ ДЛЯ ПАРСИНГА АРГУМЕНТОВ ====================

void printUsage(const std::string& programName) {
    std::cout << "Программа шифрования/дешифрования файлов" << std::endl;
    std::cout << "Использование: " << programName << " [опции]" << std::endl;
    std::cout << std::endl;
    std::cout << "Основные опции:" << std::endl;
    std::cout << "  -e, --encrypt        Режим шифрования" << std::endl;
    std::cout << "  -d, --decrypt        Режим дешифрования" << std::endl;
    std::cout << "  -i, --input FILE     Входной файл" << std::endl;
    std::cout << "  -o, --output FILE    Выходной файл" << std::endl;
    std::cout << "  -p, --password PASS  Пароль для шифрования" << std::endl;
    std::cout << "  -h, --help           Показать эту справку" << std::endl;
    std::cout << "  --auto-ext           Автоматическое управление расширениями" << std::endl;
    std::cout << std::endl;
    std::cout << "Алгоритм: AES-256 в режиме CBC" << std::endl;
    std::cout << std::endl;
    std::cout << "Требования к паролю:" << std::endl;
    std::cout << "  • Минимум 6 символов" << std::endl;
    std::cout << std::endl;
    std::cout << "Примечания:" << std::endl;
    std::cout << "  • При шифровании к имени файла автоматически добавляется .bin" << std::endl;
    std::cout << "  • При дешифровании расширение .bin автоматически убирается" << std::endl;
    std::cout << "  • Используйте --auto-ext для автоматического именования" << std::endl;
    std::cout << std::endl;
    std::cout << "Примеры:" << std::endl;
    std::cout << "  " << programName << " -e -i document.txt -o secret -p \"MyPass123\" " << std::endl;
    std::cout << "  " << programName << " -d -i secret.bin -o document -p \"MyPass123\" " << std::endl;
    std::cout << "  " << programName << " -e -i photo.jpg -o photo -p \"Secure12\" --auto-ext" << std::endl;
    std::cout << std::endl;
}

// ==================== ОСНОВНАЯ ФУНКЦИЯ ====================

int main(int argc, char* argv[]) {
    // Проверка минимального количества аргументов
    if (argc < 2) {
        printUsage(argv[0]);
        return 1;
    }
    
    // Парсинг аргументов
    CryptoProcessor::Mode mode = CryptoProcessor::ENCRYPT;
    std::string inputFile, outputFile, password;
    bool autoExtension = false;
    
    try {
        for (int i = 1; i < argc; i++) {
            std::string arg = argv[i];
            
            if (arg == "-h" || arg == "--help") {
                printUsage(argv[0]);
                return 0;
            }
            else if (arg == "-e" || arg == "--encrypt") {
                mode = CryptoProcessor::ENCRYPT;
            }
            else if (arg == "-d" || arg == "--decrypt") {
                mode = CryptoProcessor::DECRYPT;
            }
            else if ((arg == "-i" || arg == "--input") && i + 1 < argc) {
                inputFile = argv[++i];
            }
            else if ((arg == "-o" || arg == "--output") && i + 1 < argc) {
                outputFile = argv[++i];
            }
            else if ((arg == "-p" || arg == "--password") && i + 1 < argc) {
                password = argv[++i];
                
                // Проверка пароля сразу при вводе
                if (password.length() < 6) {
                    std::cerr << "Ошибка: пароль должен содержать минимум 6 символов" << std::endl;
                    std::cerr << "Ваш пароль содержит " << password.length() << " символов" << std::endl;
                    return 1;
                }
            }
            else if (arg == "--auto-ext") {
                autoExtension = true;
            }
            else if (arg == "--interactive") {
                // Интерактивный режим
                std::cout << "=== Интерактивный режим шифрования ===" << std::endl;
                
                std::cout << "Выберите действие:" << std::endl;
                std::cout << "1. Шифрование" << std::endl;
                std::cout << "2. Дешифрование" << std::endl;
                std::cout << "Ваш выбор (1/2): ";
                int choice;
                std::cin >> choice;
                mode = (choice == 1) ? CryptoProcessor::ENCRYPT : CryptoProcessor::DECRYPT;
                
                std::cout << "Входной файл: ";
                std::cin >> inputFile;
                
                std::cout << "Выходной файл (оставьте пустым для авто-именования): ";
                std::string userOutput;
                std::cin >> userOutput;
                
                if (userOutput.empty()) {
                    autoExtension = true;
                } else {
                    outputFile = userOutput;
                }
                
                // Запрос пароля с проверкой
                std::cout << "Пароль (минимум 6 символов): ";
                std::cin >> password;
                
                if (password.length() < 6) {
                    std::cerr << "Ошибка: пароль слишком короткий (" << password.length() 
                              << " символов). Минимум 6 символов." << std::endl;
                    return 1;
                }
            }
            else {
                std::cerr << "Неизвестный аргумент: " << arg << std::endl;
                printUsage(argv[0]);
                return 1;
            }
        }
        
        // Автоматическое управление расширениями
        if (autoExtension) {
            if (outputFile.empty()) {
                if (mode == CryptoProcessor::ENCRYPT) {
                    // Шифрование: добавляем .bin
                    outputFile = ensureBinExtension(inputFile);
                } else {
                    // Дешифрование: убираем .bin и добавляем _decrypted
                    outputFile = generateDecryptedName(inputFile);
                }
            } else {
                // Пользователь указал имя, но мы все равно обрабатываем расширения
                if (mode == CryptoProcessor::ENCRYPT) {
                    outputFile = ensureBinExtension(outputFile);
                }
                // Для дешифрования оставляем как есть
            }
        } else if (outputFile.empty()) {
            // Если autoExtension выключен, но выходной файл не указан
            std::cerr << "Ошибка: необходимо указать выходной файл" << std::endl;
            printUsage(argv[0]);
            return 1;
        }
        
        // Проверка обязательных параметров
        if (inputFile.empty() || outputFile.empty() || password.empty()) {
            std::cerr << "Ошибка: необходимо указать входной файл, выходной файл и пароль" << std::endl;
            printUsage(argv[0]);
            return 1;
        }
        
        // Проверка что входной и выходной файлы разные
        if (inputFile == outputFile) {
            std::cerr << "Ошибка: входной и выходной файлы не могут совпадать" << std::endl;
            return 1;
        }
        
        // Предупреждение о расширениях
        if (mode == CryptoProcessor::ENCRYPT && !hasBinExtension(outputFile) && !autoExtension) {
            std::cout << "Внимание: зашифрованный файл будет сохранен как '" << outputFile 
                      << "'. Рекомендуется использовать расширение .bin" << std::endl;
            std::cout << "Используйте --auto-ext для автоматического добавления .bin" << std::endl;
        }
        
        // Создание процессора и выполнение операции
        CryptoProcessor processor;
        
        // Вывод информации о выбранном алгоритме
        std::cout << (mode == CryptoProcessor::ENCRYPT ? "Шифрование" : "Дешифрование") 
                  << " файла: " << inputFile << std::endl;
        std::cout << "Алгоритм: " << processor.getAlgorithmInfo() << std::endl;
        std::cout << "Длина пароля: " << password.length() << " символов" << std::endl;
        if (autoExtension) {
            std::cout << "Выходной файл: " << outputFile << " (авто-именование)" << std::endl;
        }
        std::cout << "Пожалуйста, подождите..." << std::endl;
        
        // Выполнение операции
        processor.processFile(mode, inputFile, outputFile, password);
        
        std::cout << "Готово! Результат сохранен в: " << outputFile << std::endl;
        
        // Дополнительная информация
        if (mode == CryptoProcessor::ENCRYPT) {
            // Показываем размеры файлов
            std::ifstream in(inputFile, std::ios::binary | std::ios::ate);
            std::ifstream out(outputFile, std::ios::binary | std::ios::ate);
            
            if (in && out) {
                size_t inputSize = in.tellg();
                size_t outputSize = out.tellg();
                
                // Упрощенный вывод без информации о IV
                std::cout << "Размеры: исходный=" << inputSize 
                          << " байт, зашифрованный=" << outputSize 
                          << " байт" << std::endl;
            }
        }
        
    } catch (const std::exception& e) {
        std::cerr << "Ошибка: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}