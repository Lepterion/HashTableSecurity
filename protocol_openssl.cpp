// ============================================================
//  Альтернативна версія протоколу на основі OpenSSL.
//  Замість власної реалізації ChaCha20 використовує EVP API
//  бібліотеки OpenSSL (EVP_chacha20). Уся реалізація — у
//  просторі імен ossl, щоб її можна було порівнювати з ручною
//  версією з protocol.cpp у тому самому бенчмарку.
//
//  Компіляція потребує лінкування з libcrypto:  -lcrypto
// ============================================================
#include <iostream>
#include <vector>
#include <string>
#include <cstdint>
#include <array>
#include <functional>
#include <stdexcept>

#include <openssl/evp.h>
#include <openssl/rand.h>

using namespace std;

namespace ossl {

// Вузол: значення зберігається зашифрованим, IV — 16 байтів (формат OpenSSL:
// 4 байти лічильника + 12 байтів нонса).
struct SecureNode {
    string key;
    size_t key_hash;
    array<uint8_t, 16> iv;
    vector<uint8_t> ciphertext;
    SecureNode* next = nullptr;
};

class SecurityProtocol {
private:
    array<uint8_t, 32> session_key; // 256-бітний ключ сесії

    static void wipe(uint8_t* data, size_t n) {
        volatile uint8_t* p = data;
        for (size_t i = 0; i < n; ++i) p[i] = 0;
    }

    // Один прохід ChaCha20 через EVP (шифрування == дешифрування для потоку)
    static void evp_crypt(const uint8_t key[32], const uint8_t iv[16],
                          const uint8_t* in, uint8_t* out, int len) {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) throw runtime_error("EVP_CIPHER_CTX_new failed");
        int outl = 0, tmpl = 0;
        if (EVP_EncryptInit_ex(ctx, EVP_chacha20(), nullptr, key, iv) != 1 ||
            EVP_EncryptUpdate(ctx, out, &outl, in, len) != 1 ||
            EVP_EncryptFinal_ex(ctx, out + outl, &tmpl) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw runtime_error("OpenSSL ChaCha20 failed");
        }
        EVP_CIPHER_CTX_free(ctx);
    }

public:
    SecurityProtocol() {
        if (RAND_bytes(session_key.data(), (int)session_key.size()) != 1)
            throw runtime_error("RAND_bytes failed");
    }

    void encrypt(SecureNode* node, const string& plaintext) {
        if (!node) return;
        if (RAND_bytes(node->iv.data(), (int)node->iv.size()) != 1)
            throw runtime_error("RAND_bytes failed");
        node->ciphertext.resize(plaintext.size());
        evp_crypt(session_key.data(), node->iv.data(),
                  reinterpret_cast<const uint8_t*>(plaintext.data()),
                  node->ciphertext.data(), (int)plaintext.size());
    }

    string decrypt(const SecureNode* node) const {
        if (!node) return {};
        vector<uint8_t> tmp(node->ciphertext.size());
        evp_crypt(session_key.data(), node->iv.data(),
                  node->ciphertext.data(), tmp.data(),
                  (int)node->ciphertext.size());
        string result(tmp.begin(), tmp.end());
        wipe(tmp.data(), tmp.size());
        return result;
    }

    void secure_wipe(SecureNode* node) {
        if (!node) return;
        if (!node->ciphertext.empty()) {
            wipe(node->ciphertext.data(), node->ciphertext.size());
            node->ciphertext.clear();
        }
        wipe(node->iv.data(), node->iv.size());
    }

    ~SecurityProtocol() { wipe(session_key.data(), session_key.size()); }
};

// Хеш-таблиця ідентична за логікою до версії з protocol.cpp,
// але використовує OpenSSL-протокол шифрування.
class SecureHashTable {
private:
    vector<SecureNode*> buckets;
    size_t item_count;
    SecurityProtocol crypto;

    size_t index_for(size_t h) const { return h % buckets.size(); }

public:
    explicit SecureHashTable(size_t num_buckets = 16)
        : buckets(num_buckets ? num_buckets : 1, nullptr), item_count(0) {}

    SecureHashTable(const SecureHashTable&) = delete;
    SecureHashTable& operator=(const SecureHashTable&) = delete;

    ~SecureHashTable() {
        for (SecureNode* head : buckets) {
            while (head) {
                SecureNode* next = head->next;
                crypto.secure_wipe(head);
                delete head;
                head = next;
            }
        }
    }

    void insert(const string& key, const string& value) {
        size_t h = hash<string>{}(key);
        size_t idx = index_for(h);
        for (SecureNode* n = buckets[idx]; n; n = n->next) {
            if (n->key_hash == h && n->key == key) {
                crypto.encrypt(n, value);
                return;
            }
        }
        SecureNode* node = new SecureNode();
        node->key = key;
        node->key_hash = h;
        crypto.encrypt(node, value);
        node->next = buckets[idx];
        buckets[idx] = node;
        ++item_count;
    }

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

    const vector<uint8_t>* raw_bytes(const string& key) const {
        size_t h = hash<string>{}(key);
        size_t idx = h % buckets.size();
        for (SecureNode* n = buckets[idx]; n; n = n->next)
            if (n->key_hash == h && n->key == key) return &n->ciphertext;
        return nullptr;
    }
};

} // namespace ossl
