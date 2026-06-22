#include <iostream>
#include <vector>
#include <string>
#include <functional>
#include <cstdint>
#include <iomanip> // Для гарного виводу hex кодів
#include "protocol.cpp"

using namespace std;

// "Погляд хакера" — сирий дамп байтів значення
void print_memory_hex(const vector<uint8_t>& data) {
    cout << "[Raw RAM Dump]: ";
    for (size_t i = 0; i < data.size(); ++i)
        cout << hex << setw(2) << setfill('0') << (int)data[i] << " ";
    cout << dec << endl;
}

int main() {
    cout << "🛡️ Secure Vault — захищена хеш-таблиця 🛡️\n" << endl;

    // Таблиця тримає всередині власну сесію шифрування (ChaCha20)
    SecureHashTable vault(16);

    // Зберігаємо кілька секретів — у таблиці вони одразу шифруються
    vault.insert("Binance_API_Key", "abc123xyz987");
    vault.insert("DB_Password",      "qwerty!2026");
    cout << "Збережено 2 секрети у захищену таблицю." << endl;

    cout << "\n--- Спроба сканування пам'яті (Cheat Engine) ---" << endl;
    const vector<uint8_t>* raw = vault.raw_bytes("Binance_API_Key");
    print_memory_hex(*raw);
    cout << "[Text View]: " << string(raw->begin(), raw->end())
         << "  (сміття)" << endl;

    cout << "\n--- Легальний запит через API хеш-таблиці ---" << endl;
    string value;
    if (vault.find("Binance_API_Key", value))
        cout << "Binance_API_Key = " << value << endl;
    if (vault.find("DB_Password", value))
        cout << "DB_Password     = " << value << endl;

    cout << "\n--- Видалення секрету ---" << endl;
    vault.erase("Binance_API_Key");
    cout << "Binance_API_Key: "
         << (vault.find("Binance_API_Key", value) ? "ще присутній"
                                                  : "видалено та затерто")
         << endl;

    cout << "\nСесію завершено. При знищенні таблиці всі дані затираються."
         << endl;
    return 0;
}
