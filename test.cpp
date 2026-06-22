#include <iostream>
#include <vector>
#include <string>
#include <functional>
#include <cstdint>
#include <cassert>

using namespace std;

#include "protocol.cpp"

static string bytes_to_str(const vector<uint8_t>& v) {
    return string(v.begin(), v.end());
}

void run_crypto_tests() {
    cout << "--- Тести шифрування (ChaCha20) ---" << endl;

    SecurityProtocol protocol;

    SecureNode node;
    node.key = "admin_password";
    node.key_hash = hash<string>{}(node.key);

    string secret = "SuperSecret123!";
    protocol.encrypt(&node, secret);

    // 1. У пам'яті немає відкритого тексту
    assert(bytes_to_str(node.ciphertext) != secret &&
           "FATAL: дані лежать у відкритому вигляді!");
    cout << "[OK] Memory Scan: відкритий текст приховано." << endl;

    // 2. Дешифрування точно відновлює оригінал
    assert(protocol.decrypt(&node) == secret &&
           "FATAL: дані пошкоджено при дешифруванні!");
    cout << "[OK] Decrypt: дані відновлено точно." << endl;

    // 3. Однаковий текст -> різний шифротекст (унікальний нонс)
    SecureNode a, b;
    protocol.encrypt(&a, "identical_value");
    protocol.encrypt(&b, "identical_value");
    assert(a.ciphertext != b.ciphertext &&
           "FATAL: однаковий шифротекст => нонс не унікальний!");
    cout << "[OK] Nonce: однакові значення дають різний шифротекст." << endl;

    // 4. Безпечне затирання
    protocol.secure_wipe(&node);
    assert(node.ciphertext.empty() && "FATAL: вузол не затерто!");
    cout << "[OK] Secure Wipe: пам'ять затерто." << endl;
}

void run_hashtable_tests() {
    cout << "\n--- Тести хеш-таблиці ---" << endl;

    SecureHashTable table(8);
    string out;

    // insert / find
    table.insert("user1", "alpha");
    table.insert("user2", "beta");
    table.insert("user3", "gamma");
    assert(table.size() == 3);
    assert(table.find("user1", out) && out == "alpha");
    assert(table.find("user2", out) && out == "beta");
    assert(table.find("user3", out) && out == "gamma");
    cout << "[OK] Insert/Find: 3 записи коректно знайдено." << endl;

    // оновлення наявного ключа (без дублювання)
    table.insert("user1", "alpha-NEW");
    assert(table.size() == 3 && table.find("user1", out) && out == "alpha-NEW");
    cout << "[OK] Update: значення оновлено без дублювання." << endl;

    // відсутній ключ
    assert(!table.find("ghost", out));
    cout << "[OK] Miss: відсутній ключ не знайдено." << endl;

    // у сирій пам'яті таблиці немає відкритого значення
    const vector<uint8_t>* raw = table.raw_bytes("user2");
    assert(raw && bytes_to_str(*raw) != "beta");
    cout << "[OK] At-rest: значення в таблиці зашифровано." << endl;

    // erase + затирання
    assert(table.erase("user2"));
    assert(!table.find("user2", out));
    assert(table.size() == 2);
    assert(!table.erase("user2")); // повторне видалення — вже немає
    cout << "[OK] Erase: запис видалено та затерто." << endl;

    // навантаження: багато ключів у малій кількості бакетів -> колізії
    SecureHashTable big(4);
    for (int i = 0; i < 100; ++i)
        big.insert("k" + to_string(i), "v" + to_string(i));
    bool all_ok = true;
    for (int i = 0; i < 100; ++i) {
        string v;
        if (!big.find("k" + to_string(i), v) || v != "v" + to_string(i))
            all_ok = false;
    }
    assert(all_ok && big.size() == 100);
    cout << "[OK] Collisions: 100 ключів у 4 бакетах коректні." << endl;
}

int main() {
    run_crypto_tests();
    run_hashtable_tests();
    cout << "\nВсі тести пройдено успішно! Систему захищено. ✅" << endl;
    return 0;
}
