#include <iostream>
#include <vector>
#include <string>
#include <functional>
#include <cstdint>
#include <iomanip> // Для гарного виводу hex кодів
#include "the_code.cpp"

using namespace std;

// Допоміжна функція для Володимира, щоб показати "погляд хакера"
void print_memory_hex(const vector<uint8_t>& data) {
    cout << "[Raw RAM Dump]: ";
    for (int i = 0; i < data.size(); ++i) {
        // Виводимо байти у шістнадцятковому форматі, як у дебагерах
        cout << hex << setw(2) << setfill('0') << (int)data[i] << " ";
    }
    cout << dec << endl; // Повертаємо десятковий формат
}

int main() {
    cout << "🛡️ Ласкаво просимо до Secure Vault 🛡️" << endl;
    cout << "Генерація сесійного ключа..." << endl;
    
    // В реальності тут має бути рандомізатор, для демо беремо константу
    SecurityProtocol vault_protocol(133742069); 

    // Створюємо запис
    SecureNode my_secret;
    my_secret.key = "Binance_API_Key";
    my_secret.key_hash = hash<string>{}(my_secret.key);
    
    string api_key = "abc123xyz987";
    my_secret.obfuscated_value.assign(api_key.begin(), api_key.end());

    cout << "\nЗберігаємо ключ: " << api_key << " ..." << endl;
    
    // Шифруємо перед збереженням в "таблицю"
    vault_protocol.process_in_place(&my_secret);
    cout << "Запис захищено і збережено!" << endl;

    cout << "\n--- Спроба сканування пам'яті (Cheat Engine) ---" << endl;
    // Хакер дивиться в пам'ять і бачить лише незрозумілий набір байтів
    print_memory_hex(my_secret.obfuscated_value);
    
    // Намагаємося прочитати як текст
    string hacked_text(my_secret.obfuscated_value.begin(), my_secret.obfuscated_value.end());
    cout << "[Text View]: " << hacked_text << " (Сміття)" << endl;

    cout << "\n--- Легальний запит через API хеш-таблиці ---" << endl;
    // Розшифровуємо на льоту
    vault_protocol.process_in_place(&my_secret);
    string legit_text(my_secret.obfuscated_value.begin(), my_secret.obfuscated_value.end());
    cout << "Отримане значення: " << legit_text << endl;

    // Безпечно видаляємо сесію
    vault_protocol.secure_wipe(&my_secret);
    cout << "\nСесію завершено. Дані затерто." << endl;

    return 0;
}