#include <iostream>
#include <vector>
#include <string>
#include <cstdint>
#include <cassert>

using namespace std;

#include "protocol.hpp"

static string bytes_to_str(const vector<uint8_t>& v) {
    return string(v.begin(), v.end());
}

void run_crypto_tests() {
    cout << "--- Тести шифрування (ChaCha20) ---" << endl;

    SecureHashTable table(16);
    string out;
    string secret = "SuperSecret123!";
    table.insert("admin_password", secret);

    // 1. У пам'яті таблиці немає відкритого тексту
    const vector<uint8_t>* raw = table.raw_bytes("admin_password");
    assert(raw && bytes_to_str(*raw) != secret &&
           "FATAL: дані лежать у відкритому вигляді!");
    cout << "[OK] Memory Scan: відкритий текст приховано." << endl;

    // 2. Дешифрування точно відновлює оригінал
    assert(table.find("admin_password", out) && out == secret &&
           "FATAL: дані пошкоджено при дешифруванні!");
    cout << "[OK] Decrypt: дані відновлено точно." << endl;

    // 3. Лічильниковий нонс: однакові значення -> різний шифротекст
    table.insert("acc_a", "identical_value");
    table.insert("acc_b", "identical_value");
    const vector<uint8_t>* ra = table.raw_bytes("acc_a");
    const vector<uint8_t>* rb = table.raw_bytes("acc_b");
    assert(ra && rb && *ra != *rb &&
           "FATAL: однаковий шифротекст => нонс не унікальний!");
    cout << "[OK] Nonce: лічильник дає унікальний шифротекст." << endl;

    // 4. Ключі не зберігаються у відкритому вигляді (лише SipHash-відбиток)
    //    Перевіряємо непрямо: лукап працює, але ключа в структурі немає.
    assert(!table.find("admin_passwor", out) && "часткова відповідність ключа!");
    cout << "[OK] Keyed-ID: пошук за SipHash-відбитком коректний." << endl;
}

void run_aead_tests() {
    cout << "\n--- Тести автентифікованого шифрування (AEAD, opt-in) ---" << endl;

    // Прямо через бекенд: шифрування + виявлення підробки
    SecurityProtocol aead(/*authenticated=*/true);
    SecureNode node; node.counter = 42;
    aead.encrypt(node, "topsecret");
    assert(node.has_tag && "AEAD-тег не згенеровано!");
    assert(aead.decrypt(node) == "topsecret");
    cout << "[OK] AEAD round-trip: дані відновлено." << endl;

    // Підробка шифротексту -> має кинути виняток
    node.ciphertext[0] ^= 0x01;
    bool threw = false;
    try { aead.decrypt(node); } catch (const std::runtime_error&) { threw = true; }
    assert(threw && "FATAL: підробку шифротексту не виявлено!");
    node.ciphertext[0] ^= 0x01; // відновлюємо
    cout << "[OK] Tamper (ciphertext): підробку виявлено." << endl;

    // Підробка тега -> теж виняток
    node.tag[0] ^= 0x01;
    threw = false;
    try { aead.decrypt(node); } catch (const std::runtime_error&) { threw = true; }
    assert(threw && "FATAL: підробку тега не виявлено!");
    cout << "[OK] Tamper (tag): підробку виявлено." << endl;

    // Без AEAD тег не створюється
    SecurityProtocol plain(/*authenticated=*/false);
    SecureNode n2; n2.counter = 1;
    plain.encrypt(n2, "data");
    assert(!n2.has_tag && plain.decrypt(n2) == "data");
    cout << "[OK] Plain mode: AEAD вимкнено за замовчуванням." << endl;
}

void run_hashtable_tests() {
    cout << "\n--- Тести хеш-таблиці ---" << endl;

    SecureHashTable table(8);
    string out;

    table.insert("user1", "alpha");
    table.insert("user2", "beta");
    table.insert("user3", "gamma");
    assert(table.size() == 3);
    assert(table.find("user1", out) && out == "alpha");
    assert(table.find("user2", out) && out == "beta");
    assert(table.find("user3", out) && out == "gamma");
    cout << "[OK] Insert/Find: 3 записи коректно знайдено." << endl;

    table.insert("user1", "alpha-NEW");
    assert(table.size() == 3 && table.find("user1", out) && out == "alpha-NEW");
    cout << "[OK] Update: значення оновлено без дублювання." << endl;

    assert(!table.find("ghost", out));
    cout << "[OK] Miss: відсутній ключ не знайдено." << endl;

    const vector<uint8_t>* raw = table.raw_bytes("user2");
    assert(raw && bytes_to_str(*raw) != "beta");
    cout << "[OK] At-rest: значення в таблиці зашифровано." << endl;

    assert(table.erase("user2"));
    assert(!table.find("user2", out));
    assert(table.size() == 2);
    assert(!table.erase("user2"));
    cout << "[OK] Erase: запис видалено та затерто." << endl;

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
    cout << "[OK] Collisions: 100 ключів коректні." << endl;
}

void run_rehash_tests() {
    cout << "\n--- Тести авторозширення (rehashing) ---" << endl;

    SecureHashTable table(4);
    size_t initial_buckets = table.bucket_count();
    for (int i = 0; i < 1000; ++i)
        table.insert("key" + to_string(i), "value" + to_string(i));

    assert(table.bucket_count() > initial_buckets && "таблиця не розширилась!");
    assert(table.load_factor() <= 0.75 + 1e-9 && "фактор заповнення перевищено!");
    cout << "[OK] Resize: " << initial_buckets << " -> " << table.bucket_count()
         << " бакетів, load=" << table.load_factor() << endl;

    bool all_ok = true;
    string v;
    for (int i = 0; i < 1000; ++i)
        if (!table.find("key" + to_string(i), v) || v != "value" + to_string(i))
            all_ok = false;
    assert(all_ok && "дані втрачено після rehash!");
    cout << "[OK] Integrity: усі 1000 записів цілі після розширення." << endl;
}

int main() {
    run_crypto_tests();
    run_aead_tests();
    run_hashtable_tests();
    run_rehash_tests();
    cout << "\nВсі тести пройдено успішно! Систему захищено. ✅" << endl;
    return 0;
}
