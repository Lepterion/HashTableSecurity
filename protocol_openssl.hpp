#pragma once
// ============================================================
//  Альтернативний бекенд на OpenSSL (EVP).
//  Перевикористовує SecureTable<>, SipHash-ідентичність,
//  лічильниковий нонс і захист пам'яті з protocol.hpp.
//  Підтримує той самий опційний режим AEAD (ChaCha20-Poly1305).
//
//  Лінкування:  -lcrypto
// ============================================================
#include "protocol.hpp"

#include <stdexcept>
#include <openssl/evp.h>
#include <openssl/rand.h>

namespace ossl {

class OpenSSLBackend {
private:
    std::array<uint8_t, 32> key_;
    bool authenticated_;

    static void nonce_from_counter(uint64_t c, uint8_t nonce[12]) {
        for (int i = 0; i < 8; ++i) nonce[i] = (uint8_t)(c >> (8 * i));
        nonce[8] = nonce[9] = nonce[10] = nonce[11] = 0;
    }

public:
    explicit OpenSSLBackend(bool authenticated = false) : authenticated_(authenticated) {
        if (RAND_bytes(key_.data(), (int)key_.size()) != 1)
            throw std::runtime_error("RAND_bytes failed");
        sht::lock_mem(key_.data(), key_.size());
    }
    OpenSSLBackend(const OpenSSLBackend&) = delete;
    OpenSSLBackend& operator=(const OpenSSLBackend&) = delete;
    ~OpenSSLBackend() {
        sht::secure_wipe(key_.data(), key_.size());
        sht::unlock_mem(key_.data(), key_.size());
    }

    bool authenticated() const { return authenticated_; }

    void encrypt(sht::SecureNode& node, const std::string& pt) {
        uint8_t nonce[12]; nonce_from_counter(node.counter, nonce);
        node.ciphertext.resize(pt.size());
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");
        int outl = 0, tmpl = 0;
        const uint8_t* in = reinterpret_cast<const uint8_t*>(pt.data());
        try {
            if (authenticated_) {
                uint8_t iv[12]; std::memcpy(iv, nonce, 12);
                if (EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, key_.data(), iv) != 1 ||
                    EVP_EncryptUpdate(ctx, node.ciphertext.data(), &outl, in, (int)pt.size()) != 1 ||
                    EVP_EncryptFinal_ex(ctx, node.ciphertext.data() + outl, &tmpl) != 1 ||
                    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, node.tag.data()) != 1)
                    throw std::runtime_error("OpenSSL AEAD encrypt failed");
                node.has_tag = true;
            } else {
                uint8_t iv[16] = {0}; std::memcpy(iv + 4, nonce, 12); // [counter=0][nonce]
                if (EVP_EncryptInit_ex(ctx, EVP_chacha20(), nullptr, key_.data(), iv) != 1 ||
                    EVP_EncryptUpdate(ctx, node.ciphertext.data(), &outl, in, (int)pt.size()) != 1 ||
                    EVP_EncryptFinal_ex(ctx, node.ciphertext.data() + outl, &tmpl) != 1)
                    throw std::runtime_error("OpenSSL encrypt failed");
                node.has_tag = false;
            }
        } catch (...) { EVP_CIPHER_CTX_free(ctx); throw; }
        EVP_CIPHER_CTX_free(ctx);
    }

    std::string decrypt(const sht::SecureNode& node) const {
        uint8_t nonce[12]; nonce_from_counter(node.counter, nonce);
        std::vector<uint8_t> out(node.ciphertext.size());
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");
        int outl = 0, tmpl = 0;
        try {
            if (authenticated_) {
                uint8_t iv[12]; std::memcpy(iv, nonce, 12);
                uint8_t tag[16]; std::memcpy(tag, node.tag.data(), 16);
                if (EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, key_.data(), iv) != 1 ||
                    EVP_DecryptUpdate(ctx, out.data(), &outl,
                                      node.ciphertext.data(), (int)node.ciphertext.size()) != 1 ||
                    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, tag) != 1)
                    throw std::runtime_error("OpenSSL AEAD decrypt setup failed");
                if (EVP_DecryptFinal_ex(ctx, out.data() + outl, &tmpl) != 1)
                    throw std::runtime_error("authentication failed: дані підроблено");
            } else {
                uint8_t iv[16] = {0}; std::memcpy(iv + 4, nonce, 12);
                if (EVP_DecryptInit_ex(ctx, EVP_chacha20(), nullptr, key_.data(), iv) != 1 ||
                    EVP_DecryptUpdate(ctx, out.data(), &outl,
                                      node.ciphertext.data(), (int)node.ciphertext.size()) != 1 ||
                    EVP_DecryptFinal_ex(ctx, out.data() + outl, &tmpl) != 1)
                    throw std::runtime_error("OpenSSL decrypt failed");
            }
        } catch (...) { EVP_CIPHER_CTX_free(ctx); throw; }
        EVP_CIPHER_CTX_free(ctx);
        std::string r(out.begin(), out.end());
        sht::secure_wipe(out.data(), out.size());
        return r;
    }
};

using SecureHashTable = sht::SecureTable<OpenSSLBackend>;

} // namespace ossl
