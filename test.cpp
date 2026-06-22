#include <iostream>
#include <vector>
#include <string>
#include <functional>
#include <cstdint>
#include <cassert>

using namespace std;

#include "the_code.cpp"

void run_security_tests() {
    cout << "--- Запуск тестів безпеки (Дмитро) ---" << endl;

    SecurityProtocol protocol(999888777); // Тестовий ключ сесії
    
    // 1. Створюємо фейковий вузол таблиці
    SecureNode test_node;
    test_node.key = "admin_password";
    test_node.key_hash = hash<string>{}(test_node.key);
    
    // Імітуємо конвертацію рядка в байти (так працюватиме ваша таблиця)
    string secret = "SuperSecret123!";
    test_node.obfuscated_value.assign(secret.begin(), secret.end());

    // 2. Тест: ШИФРУВАННЯ IN-PLACE
    protocol.process_in_place(&test_node);
    
    // Перевіряємо, що байти в пам'яті більше НЕ дорівнюють оригіналу
    string memory_dump(test_node.obfuscated_value.begin(), test_node.obfuscated_value.end());
    assert(memory_dump != secret && "FATAL: Дані в пам'яті лежать у відкритому вигляді!");
    cout << "[OK] Memory Scan Test: Оригінальний текст приховано." << endl;

    // 3. Тест: ДЕШИФРУВАННЯ
    protocol.process_in_place(&test_node); // Повторний прохід повертає оригінал
    string decrypted(test_node.obfuscated_value.begin(), test_node.obfuscated_value.end());
    assert(decrypted == secret && "FATAL: Дані пошкоджено при розшифруванні!");
    cout << "[OK] Decryption Test: Дані успішно відновлено." << endl;

    // 4. Тест: БЕЗПЕЧНЕ ЗАТИРАННЯ
    protocol.secure_wipe(&test_node);
    assert(test_node.obfuscated_value.empty() && "FATAL: Вектор не очистився!");
    cout << "[OK] Secure Wipe Test: Пам'ять успішно затерта та звільнена." << endl;
    
    cout << "Всі тести пройдено успішно! Систему захищено." << endl;
}
/*
int main() {
    run_security_tests();
    return 0;
}
*/