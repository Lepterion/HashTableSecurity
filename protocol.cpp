#include <iostream>
#include <vector>
#include <string>
#include <cstdint>
#include <cstring>
#include <array>
#include <random>
#include <algorithm>
#include <functional> // Для hash

using namespace std;

// ============================================================
//  ChaCha20 — потоковий шифр (RFC 8439).
//  Справжнє шифрування замість простого XOR-маскування.
//  Реалізовано з нуля, без зовнішніх бібліотек.
// ============================================================
namespace chacha {

    static inline uint32_t rotl32(uint32_t x, int n) {
        return (x << n) | (x >> (32 - n));
    }

    static inline uint32_t load32_le(const uint8_t* p) {
        return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
               ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
    }

    // Чверть-раунд ChaCha20 (ARX: add-rotate-xor)
    static inline void quarter_round(uint32_t& a, uint32_t& b,
                                     uint32_t& c, uint32_t& d) {
        a += b; d ^= a; d = rotl32(d, 16);
        c += d; b ^= c; b = rotl32(b, 12);
        a += b; d ^= a; d = rotl32(d, 8);
        c += d; b ^= c; b = rotl32(b, 7);
    }

    // Генерує один 64-байтовий блок потоку ключа
    static void block(const uint8_t key[32], const uint8_t nonce[12],
                      uint32_t counter, uint8_t out[64]) {
        // Константа "expand 32-byte k"
        static const uint32_t C[4] = {
            0x61707865, 0x3320646e, 0x79622d32, 0x6b206574
        };
        uint32_t state[16];
        state[0] = C[0]; state[1] = C[1]; state[2] = C[2]; state[3] = C[3];
        for (int i = 0; i < 8; ++i) state[4 + i] = load32_le(key + 4 * i);
        state[12] = counter;
        state[13] = load32_le(nonce + 0);
        state[14] = load32_le(nonce + 4);
        state[15] = load32_le(nonce + 8);

        uint32_t w[16];
        memcpy(w, state, sizeof(w));

        // 20 раундів = 10 ітерацій (стовпці + діагоналі)
        for (int i = 0; i < 10; ++i) {
            quarter_round(w[0], w[4], w[8],  w[12]);
            quarter_round(w[1], w[5], w[9],  w[13]);
            quarter_round(w[2], w[6], w[10], w[14]);
            quarter_round(w[3], w[7], w[11], w[15]);
            quarter_round(w[0], w[5], w[10], w[15]);
            quarter_round(w[1], w[6], w[11], w[12]);
            quarter_round(w[2], w[7], w[8],  w[13]);
            quarter_round(w[3], w[4], w[9],  w[14]);
        }

        // Додаємо початковий стан і серіалізуємо little-endian
        for (int i = 0; i < 16; ++i) {
            uint32_t v = w[i] + state[i];
            out[4 * i + 0] = (uint8_t)(v);
            out[4 * i + 1] = (uint8_t)(v >> 8);
            out[4 * i + 2] = (uint8_t)(v >> 16);
            out[4 * i + 3] = (uint8_t)(v >> 24);
        }
    }

    // XOR даних з потоком ключа. Та сама операція шифрує і дешифрує.
    static void xor_stream(const uint8_t key[32], const uint8_t nonce[12],
                           uint8_t* data, size_t len) {
        uint8_t ks[64];
        uint32_t counter = 1; // RFC 8439: лічильник корисного навантаження з 1
        size_t off = 0;
        while (off < len) {
            block(key, nonce, counter++, ks);
            size_t n = min((size_t)64, len - off);
            for (size_t i = 0; i < n; ++i) data[off + i] ^= ks[i];
            off += n;
        }
        // Затираємо локальний буфер потоку ключа
        volatile uint8_t* p = ks;
        for (int i = 0; i < 64; ++i) p[i] = 0;
    }

} // namespace chacha

// ============================================================
//  Вузол таблиці. Значення зберігається ЗАШИФРОВАНИМ ("at rest").
// ============================================================
struct SecureNode {
    string key;
    size_t key_hash;
    array<uint8_t, 12> nonce;     // унікальний нонс для цього значення
    vector<uint8_t> ciphertext;   // зашифроване значення
    SecureNode* next = nullptr;
};

// ============================================================
//  Протокол безпеки: тримає сесійний ключ і шифрує/дешифрує вузли.
// ============================================================
class SecurityProtocol {
private:
    array<uint8_t, 32> session_key; // 256-бітний ключ сесії
    mt19937_64 rng;                 // джерело випадкових нонсів

    void fill_random(uint8_t* buf, size_t n) {
        for (size_t i = 0; i < n; ++i)
            buf[i] = (uint8_t)(rng() & 0xff);
    }

    static void wipe(uint8_t* data, size_t n) {
        // volatile забороняє компілятору викинути затирання при оптимізації
        volatile uint8_t* p = data;
        for (size_t i = 0; i < n; ++i) p[i] = 0;
    }

public:
    SecurityProtocol() {
        random_device rd; // системне джерело ентропії
        seed_seq seq{ rd(), rd(), rd(), rd(), rd(), rd(), rd(), rd() };
        rng.seed(seq);
        fill_random(session_key.data(), session_key.size());
    }

    // Шифрує plaintext і кладе шифротекст у вузол (новий нонс щоразу)
    void encrypt(SecureNode* node, const string& plaintext) {
        if (!node) return;
        fill_random(node->nonce.data(), node->nonce.size());
        node->ciphertext.assign(plaintext.begin(), plaintext.end());
        chacha::xor_stream(session_key.data(), node->nonce.data(),
                           node->ciphertext.data(), node->ciphertext.size());
    }

    // Дешифрує у тимчасовий рядок; збережене значення лишається зашифрованим
    string decrypt(const SecureNode* node) const {
        if (!node) return {};
        vector<uint8_t> tmp = node->ciphertext;
        chacha::xor_stream(session_key.data(), node->nonce.data(),
                           tmp.data(), tmp.size());
        string result(tmp.begin(), tmp.end());
        wipe(tmp.data(), tmp.size()); // затираємо тимчасовий буфер
        return result;
    }

    // Безпечне затирання даних вузла перед знищенням
    void secure_wipe(SecureNode* node) {
        if (!node) return;
        if (!node->ciphertext.empty()) {
            wipe(node->ciphertext.data(), node->ciphertext.size());
            node->ciphertext.clear();
        }
        wipe(node->nonce.data(), node->nonce.size());
    }

    ~SecurityProtocol() {
        wipe(session_key.data(), session_key.size()); // затираємо ключ сесії
    }
};

// ============================================================
//  SecureHashTable — справжня хеш-таблиця з ланцюжковим
//  вирішенням колізій. Значення завжди зашифровані в пам'яті.
// ============================================================
class SecureHashTable {
private:
    vector<SecureNode*> buckets;
    size_t item_count;
    SecurityProtocol crypto; // власна сесія шифрування для цієї таблиці

    size_t index_for(size_t h) const { return h % buckets.size(); }

public:
    explicit SecureHashTable(size_t num_buckets = 16)
        : buckets(num_buckets ? num_buckets : 1, nullptr), item_count(0) {}

    // Володіє сирими вузлами — копіювання заборонене (щоб уникнути double-free)
    SecureHashTable(const SecureHashTable&) = delete;
    SecureHashTable& operator=(const SecureHashTable&) = delete;

    ~SecureHashTable() {
        for (SecureNode* head : buckets) {
            while (head) {
                SecureNode* next = head->next;
                crypto.secure_wipe(head); // затираємо перед звільненням
                delete head;
                head = next;
            }
        }
    }

    // Вставка нового або оновлення наявного запису
    void insert(const string& key, const string& value) {
        size_t h = hash<string>{}(key);
        size_t idx = index_for(h);

        for (SecureNode* n = buckets[idx]; n; n = n->next) {
            if (n->key_hash == h && n->key == key) {
                crypto.encrypt(n, value); // оновлюємо значення
                return;
            }
        }
        SecureNode* node = new SecureNode();
        node->key = key;
        node->key_hash = h;
        crypto.encrypt(node, value);
        node->next = buckets[idx]; // вставка на початок ланцюжка
        buckets[idx] = node;
        ++item_count;
    }

    // Пошук: дешифрує значення в out_value, повертає true якщо знайдено
    bool find(const string& key, string& out_value) const {
        size_t h = hash<string>{}(key);
        size_t idx = h % buckets.size();
        for (SecureNode* n = buckets[idx]; n; n = n->next) {
            if (n->key_hash == h && n->key == key) {
                out_value = crypto.decrypt(n);
                return true;
            }
        }
        return false;
    }

    // Видалення із безпечним затиранням пам'яті
    bool erase(const string& key) {
        size_t h = hash<string>{}(key);
        size_t idx = h % buckets.size();
        SecureNode* prev = nullptr;
        for (SecureNode* n = buckets[idx]; n; prev = n, n = n->next) {
            if (n->key_hash == h && n->key == key) {
                if (prev) prev->next = n->next;
                else      buckets[idx] = n->next;
                crypto.secure_wipe(n);
                delete n;
                --item_count;
                return true;
            }
        }
        return false;
    }

    size_t size() const { return item_count; }
    size_t bucket_count() const { return buckets.size(); }

    // Лише для демонстрації "погляду хакера": сирий шифротекст значення
    const vector<uint8_t>* raw_bytes(const string& key) const {
        size_t h = hash<string>{}(key);
        size_t idx = h % buckets.size();
        for (SecureNode* n = buckets[idx]; n; n = n->next)
            if (n->key_hash == h && n->key == key) return &n->ciphertext;
        return nullptr;
    }
};
