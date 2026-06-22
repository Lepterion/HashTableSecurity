#include <iostream>
#include <vector>
#include <string>
#include <cstdint>
#include <functional> // Для hash

using namespace std;

// Наш вузол таблиці
struct SecureNode {
    string key;
    size_t key_hash;
    vector<uint8_t> obfuscated_value;
    SecureNode* next;
};

class SecurityProtocol {
private:
    uint64_t session_key; // Динамічний ключ, що генерується при запуску

public:
    // Конструктор ініціалізує сесію унікальним ключем
    SecurityProtocol(uint64_t generated_key) : session_key(generated_key) {}

    // Універсальна функція: робить In-Place шифрування ТА дешифрування
    void process_in_place(SecureNode* node) {
        if (!node || node->obfuscated_value.empty()) return;

        // 1. Формуємо унікальну маску для цього конкретного вузла
        uint64_t node_mask = session_key ^ node->key_hash;
        
        // 2. Розбиваємо 64-бітну маску на 8 окремих байтів
        uint8_t* mask_bytes = reinterpret_cast<uint8_t*>(&node_mask);
        
        // 3. Мануальний In-Place XOR прохід по масиву даних.
        size_t data_size = node->obfuscated_value.size();
        for (size_t i = 0; i < data_size; ++i) {
            node->obfuscated_value[i] ^= mask_bytes[i % 8];
        }
    }

    // Безпечне видалення (Secure Wiping) - затирання пам'яті перед знищенням
    void secure_wipe(SecureNode* node) {
        if (!node || node->obfuscated_value.empty()) return;

        size_t data_size = node->obfuscated_value.size();
        
        // Використовуємо volatile вказівник для заборони оптимізації компілятором
        volatile uint8_t* data_ptr = node->obfuscated_value.data();
        
        // Мануально заповнюємо пам'ять нулями
        for (size_t i = 0; i < data_size; ++i) {
            data_ptr[i] = 0;
        }
        
        // Тільки тепер безпечно очищаємо вектор
        node->obfuscated_value.clear();
    }
};
/*
int main() {
    // Створюємо екземпляр нашого протоколу з випадковим ключем (наприклад, 12345)
    SecurityProtocol protocol(12345);
    
    cout << "Протокол безпеки успішно ініціалізовано!" << endl;
    
    return 0;
} */