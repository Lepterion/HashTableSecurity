#pragma once
// ============================================================
//  Secure Hash Table — header-only ядро.
//  Містить криптопримітиви (ChaCha20 / Poly1305 / SipHash),
//  ручний бекенд шифрування та шаблон таблиці SecureTable<Backend>.
//
//  Усі примітиви перевірено офіційними тест-векторами:
//    ChaCha20  — RFC 8439 §2.4.2
//    Poly1305  — RFC 8439 §2.5.2
//    AEAD      — RFC 8439 §2.8.2 (ChaCha20-Poly1305)
//    SipHash   — еталонні вектори SipHash-2-4
// ============================================================
#include <vector>
#include <string>
#include <cstdint>
#include <cstring>
#include <array>
#include <random>
#include <algorithm>
#include <utility>
#include <stdexcept>

#if defined(__has_include)
#  if __has_include(<sys/mman.h>)
#    include <sys/mman.h>
#    define SHT_HAVE_MLOCK 1
#  endif
#endif

namespace sht {

// ---------- Затирання пам'яті ----------
inline void secure_wipe(void* data, size_t n) {
    volatile uint8_t* p = static_cast<volatile uint8_t*>(data);
    for (size_t i = 0; i < n; ++i) p[i] = 0;
}

// ---------- Блокування сторінок у RAM (заборона свопу), best-effort ----------
inline void lock_mem(void* p, size_t n) {
#ifdef SHT_HAVE_MLOCK
    ::mlock(p, n); // ігноруємо помилку: може не вистачати привілеїв
#else
    (void)p; (void)n;
#endif
}
inline void unlock_mem(void* p, size_t n) {
#ifdef SHT_HAVE_MLOCK
    ::munlock(p, n);
#else
    (void)p; (void)n;
#endif
}

// ---------- Випадкові байти із системного джерела ентропії ----------
inline void fill_random_bytes(uint8_t* buf, size_t n) {
    static thread_local std::random_device rd;
    size_t i = 0;
    while (i < n) {
        uint32_t r = rd();
        for (int b = 0; b < 4 && i < n; ++b, ++i) buf[i] = (uint8_t)(r >> (8 * b));
    }
}

// ---------- Порівняння за сталий час ----------
inline bool ct_equal(const uint8_t* a, const uint8_t* b, size_t n) {
    uint8_t r = 0;
    for (size_t i = 0; i < n; ++i) r |= (uint8_t)(a[i] ^ b[i]);
    return r == 0;
}

static inline uint32_t load32_le(const uint8_t* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

// ============================================================
//  ChaCha20 (RFC 8439)
// ============================================================
namespace chacha {

    static inline uint32_t rotl32(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }

    static inline void quarter_round(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d) {
        a += b; d ^= a; d = rotl32(d, 16);
        c += d; b ^= c; b = rotl32(b, 12);
        a += b; d ^= a; d = rotl32(d, 8);
        c += d; b ^= c; b = rotl32(b, 7);
    }

    inline void block(const uint8_t key[32], const uint8_t nonce[12],
                      uint32_t counter, uint8_t out[64]) {
        static const uint32_t C[4] = { 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574 };
        uint32_t s[16];
        s[0] = C[0]; s[1] = C[1]; s[2] = C[2]; s[3] = C[3];
        for (int i = 0; i < 8; ++i) s[4 + i] = load32_le(key + 4 * i);
        s[12] = counter;
        s[13] = load32_le(nonce + 0);
        s[14] = load32_le(nonce + 4);
        s[15] = load32_le(nonce + 8);
        uint32_t w[16];
        std::memcpy(w, s, sizeof(w));
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
        for (int i = 0; i < 16; ++i) {
            uint32_t v = w[i] + s[i];
            out[4 * i + 0] = (uint8_t)(v);
            out[4 * i + 1] = (uint8_t)(v >> 8);
            out[4 * i + 2] = (uint8_t)(v >> 16);
            out[4 * i + 3] = (uint8_t)(v >> 24);
        }
    }

    // XOR із потоком ключа, лічильник починається з заданого (RFC: дані з 1)
    inline void xor_stream(const uint8_t key[32], const uint8_t nonce[12],
                           uint8_t* data, size_t len, uint32_t counter = 1) {
        uint8_t ks[64];
        size_t off = 0;
        while (off < len) {
            block(key, nonce, counter++, ks);
            size_t n = std::min((size_t)64, len - off);
            for (size_t i = 0; i < n; ++i) data[off + i] ^= ks[i];
            off += n;
        }
        secure_wipe(ks, sizeof(ks));
    }

} // namespace chacha

// ============================================================
//  Poly1305 (RFC 8439) — реалізація poly1305-donna (32-біт)
// ============================================================
inline void poly1305(uint8_t mac[16], const uint8_t* m, size_t bytes, const uint8_t key[32]) {
    uint32_t t0 = load32_le(key + 0), t1 = load32_le(key + 4),
             t2 = load32_le(key + 8), t3 = load32_le(key + 12);
    uint32_t r0 = t0 & 0x3ffffff,
             r1 = ((t0 >> 26) | (t1 << 6)) & 0x3ffff03,
             r2 = ((t1 >> 20) | (t2 << 12)) & 0x3ffc0ff,
             r3 = ((t2 >> 14) | (t3 << 18)) & 0x3f03fff,
             r4 = (t3 >> 8) & 0x00fffff;
    uint32_t s1 = r1 * 5, s2 = r2 * 5, s3 = r3 * 5, s4 = r4 * 5;
    uint32_t h0 = 0, h1 = 0, h2 = 0, h3 = 0, h4 = 0;

    auto mulr = [&]() {
        uint64_t d0 = (uint64_t)h0*r0 + (uint64_t)h1*s4 + (uint64_t)h2*s3 + (uint64_t)h3*s2 + (uint64_t)h4*s1;
        uint64_t d1 = (uint64_t)h0*r1 + (uint64_t)h1*r0 + (uint64_t)h2*s4 + (uint64_t)h3*s3 + (uint64_t)h4*s2;
        uint64_t d2 = (uint64_t)h0*r2 + (uint64_t)h1*r1 + (uint64_t)h2*r0 + (uint64_t)h3*s4 + (uint64_t)h4*s3;
        uint64_t d3 = (uint64_t)h0*r3 + (uint64_t)h1*r2 + (uint64_t)h2*r1 + (uint64_t)h3*r0 + (uint64_t)h4*s4;
        uint64_t d4 = (uint64_t)h0*r4 + (uint64_t)h1*r3 + (uint64_t)h2*r2 + (uint64_t)h3*r1 + (uint64_t)h4*r0;
        uint32_t c;
        c = (uint32_t)(d0 >> 26); h0 = (uint32_t)d0 & 0x3ffffff;
        d1 += c; c = (uint32_t)(d1 >> 26); h1 = (uint32_t)d1 & 0x3ffffff;
        d2 += c; c = (uint32_t)(d2 >> 26); h2 = (uint32_t)d2 & 0x3ffffff;
        d3 += c; c = (uint32_t)(d3 >> 26); h3 = (uint32_t)d3 & 0x3ffffff;
        d4 += c; c = (uint32_t)(d4 >> 26); h4 = (uint32_t)d4 & 0x3ffffff;
        h0 += c * 5; c = h0 >> 26; h0 &= 0x3ffffff; h1 += c;
    };

    while (bytes >= 16) {
        h0 += load32_le(m + 0) & 0x3ffffff;
        h1 += (load32_le(m + 3) >> 2) & 0x3ffffff;
        h2 += (load32_le(m + 6) >> 4) & 0x3ffffff;
        h3 += (load32_le(m + 9) >> 6) & 0x3ffffff;
        h4 += (load32_le(m + 12) >> 8) | (1 << 24);
        mulr(); m += 16; bytes -= 16;
    }
    if (bytes) {
        uint8_t b[16]; size_t i;
        for (i = 0; i < bytes; ++i) b[i] = m[i];
        b[i++] = 1; for (; i < 16; ++i) b[i] = 0;
        h0 += load32_le(b + 0) & 0x3ffffff;
        h1 += (load32_le(b + 3) >> 2) & 0x3ffffff;
        h2 += (load32_le(b + 6) >> 4) & 0x3ffffff;
        h3 += (load32_le(b + 9) >> 6) & 0x3ffffff;
        h4 += (load32_le(b + 12) >> 8);
        mulr();
    }
    uint32_t c;
    c = h1 >> 26; h1 &= 0x3ffffff; h2 += c;
    c = h2 >> 26; h2 &= 0x3ffffff; h3 += c;
    c = h3 >> 26; h3 &= 0x3ffffff; h4 += c;
    c = h4 >> 26; h4 &= 0x3ffffff; h0 += c * 5;
    c = h0 >> 26; h0 &= 0x3ffffff; h1 += c;
    uint32_t g0 = h0 + 5; c = g0 >> 26; g0 &= 0x3ffffff;
    uint32_t g1 = h1 + c; c = g1 >> 26; g1 &= 0x3ffffff;
    uint32_t g2 = h2 + c; c = g2 >> 26; g2 &= 0x3ffffff;
    uint32_t g3 = h3 + c; c = g3 >> 26; g3 &= 0x3ffffff;
    uint32_t g4 = h4 + c - (1u << 26);
    uint32_t mask = (g4 >> 31) - 1;
    g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask;
    mask = ~mask;
    h0 = (h0 & mask) | g0; h1 = (h1 & mask) | g1; h2 = (h2 & mask) | g2;
    h3 = (h3 & mask) | g3; h4 = (h4 & mask) | g4;
    h0 = (h0 | (h1 << 26));
    h1 = ((h1 >> 6) | (h2 << 20));
    h2 = ((h2 >> 12) | (h3 << 14));
    h3 = ((h3 >> 18) | (h4 << 8));
    uint64_t f;
    uint32_t p0 = load32_le(key + 16), p1 = load32_le(key + 20),
             p2 = load32_le(key + 24), p3 = load32_le(key + 28);
    f = (uint64_t)h0 + p0;            h0 = (uint32_t)f;
    f = (uint64_t)h1 + p1 + (f >> 32); h1 = (uint32_t)f;
    f = (uint64_t)h2 + p2 + (f >> 32); h2 = (uint32_t)f;
    f = (uint64_t)h3 + p3 + (f >> 32); h3 = (uint32_t)f;
    auto st = [](uint8_t* o, uint32_t v) { o[0] = v; o[1] = v >> 8; o[2] = v >> 16; o[3] = v >> 24; };
    st(mac + 0, h0); st(mac + 4, h1); st(mac + 8, h2); st(mac + 12, h3);
}

// Тег AEAD ChaCha20-Poly1305 (RFC 8439 §2.8) для шифротексту ct (без AAD)
inline void aead_tag(const uint8_t key[32], const uint8_t nonce[12],
                     const uint8_t* ct, size_t ctl, uint8_t tag[16]) {
    uint8_t blk0[64];
    chacha::block(key, nonce, 0, blk0); // одноразовий ключ Poly1305 = блок з лічильником 0
    uint8_t pk[32]; std::memcpy(pk, blk0, 32);
    std::vector<uint8_t> mac(ct, ct + ctl);
    while (mac.size() % 16) mac.push_back(0);
    uint8_t lens[16] = {0};
    uint64_t c = ctl; // AAD довжини 0
    for (int i = 0; i < 8; ++i) lens[8 + i] = (uint8_t)(c >> (8 * i));
    mac.insert(mac.end(), lens, lens + 16);
    poly1305(tag, mac.data(), mac.size(), pk);
    secure_wipe(blk0, sizeof(blk0));
    secure_wipe(pk, sizeof(pk));
}

// ============================================================
//  SipHash-2-4 (64-біт) — keyed-хеш для відбитків ключів
// ============================================================
inline uint64_t siphash24(const uint8_t* in, size_t inlen, const uint8_t k[16]) {
    auto rotl = [](uint64_t x, int b) { return (x << b) | (x >> (64 - b)); };
    uint64_t k0 = 0, k1 = 0;
    for (int i = 0; i < 8; ++i) { k0 |= (uint64_t)k[i] << (8 * i); k1 |= (uint64_t)k[8 + i] << (8 * i); }
    uint64_t v0 = 0x736f6d6570736575ULL ^ k0, v1 = 0x646f72616e646f6dULL ^ k1,
             v2 = 0x6c7967656e657261ULL ^ k0, v3 = 0x7465646279746573ULL ^ k1;
    auto round = [&]() {
        v0 += v1; v1 = rotl(v1, 13); v1 ^= v0; v0 = rotl(v0, 32);
        v2 += v3; v3 = rotl(v3, 16); v3 ^= v2;
        v0 += v3; v3 = rotl(v3, 21); v3 ^= v0;
        v2 += v1; v1 = rotl(v1, 17); v1 ^= v2; v2 = rotl(v2, 32);
    };
    size_t left = inlen & 7;
    uint64_t b = (uint64_t)inlen << 56;
    const uint8_t* end = in + inlen - left;
    for (; in != end; in += 8) {
        uint64_t m = 0; for (int i = 0; i < 8; ++i) m |= (uint64_t)in[i] << (8 * i);
        v3 ^= m; round(); round(); v0 ^= m;
    }
    for (size_t i = 0; i < left; ++i) b |= (uint64_t)in[i] << (8 * i);
    v3 ^= b; round(); round(); v0 ^= b;
    v2 ^= 0xff; round(); round(); round(); round();
    return v0 ^ v1 ^ v2 ^ v3;
}

// ============================================================
//  Вузол: НЕ зберігає відкритий ключ — лише його 128-бітний
//  keyed-відбиток. Значення завжди зашифроване.
// ============================================================
struct SecureNode {
    uint64_t fp0 = 0, fp1 = 0;     // SipHash-відбиток ключа (ідентичність)
    uint64_t counter = 0;          // джерело унікального нонса
    std::vector<uint8_t> ciphertext;
    std::array<uint8_t, 16> tag{}; // Poly1305 (лише в режимі AEAD)
    bool has_tag = false;
    SecureNode* next = nullptr;
};

inline void wipe_node(SecureNode& n) {
    if (!n.ciphertext.empty()) {
        secure_wipe(n.ciphertext.data(), n.ciphertext.size());
        n.ciphertext.clear();
    }
    secure_wipe(n.tag.data(), n.tag.size());
    n.fp0 = n.fp1 = n.counter = 0; n.has_tag = false;
}

// ============================================================
//  Ручний бекенд шифрування (ChaCha20 / опційно ChaCha20-Poly1305)
// ============================================================
class ManualBackend {
private:
    std::array<uint8_t, 32> key_;
    bool authenticated_;

    static void nonce_from_counter(uint64_t c, uint8_t nonce[12]) {
        for (int i = 0; i < 8; ++i) nonce[i] = (uint8_t)(c >> (8 * i));
        nonce[8] = nonce[9] = nonce[10] = nonce[11] = 0;
    }

public:
    explicit ManualBackend(bool authenticated = false) : authenticated_(authenticated) {
        fill_random_bytes(key_.data(), key_.size());
        lock_mem(key_.data(), key_.size());
    }
    ManualBackend(const ManualBackend&) = delete;
    ManualBackend& operator=(const ManualBackend&) = delete;
    ~ManualBackend() {
        secure_wipe(key_.data(), key_.size());
        unlock_mem(key_.data(), key_.size());
    }

    bool authenticated() const { return authenticated_; }

    void encrypt(SecureNode& node, const std::string& pt) {
        uint8_t nonce[12]; nonce_from_counter(node.counter, nonce);
        node.ciphertext.assign(pt.begin(), pt.end());
        chacha::xor_stream(key_.data(), nonce, node.ciphertext.data(), node.ciphertext.size());
        if (authenticated_) {
            aead_tag(key_.data(), nonce, node.ciphertext.data(), node.ciphertext.size(), node.tag.data());
            node.has_tag = true;
        } else {
            node.has_tag = false;
        }
    }

    std::string decrypt(const SecureNode& node) const {
        uint8_t nonce[12]; nonce_from_counter(node.counter, nonce);
        if (authenticated_) {
            uint8_t t[16];
            aead_tag(key_.data(), nonce, node.ciphertext.data(), node.ciphertext.size(), t);
            if (!ct_equal(t, node.tag.data(), 16))
                throw std::runtime_error("authentication failed: дані підроблено");
        }
        std::vector<uint8_t> tmp(node.ciphertext.begin(), node.ciphertext.end());
        chacha::xor_stream(key_.data(), nonce, tmp.data(), tmp.size());
        std::string r(tmp.begin(), tmp.end());
        secure_wipe(tmp.data(), tmp.size());
        return r;
    }
};

// ============================================================
//  SecureTable<Backend> — хеш-таблиця з ланцюжками,
//  авторозширенням, SipHash-ідентичністю та лічильниковим нонсом.
// ============================================================
template <class Backend>
class SecureTable {
private:
    std::vector<SecureNode*> buckets_;
    size_t count_;
    uint64_t next_counter_;
    std::array<uint8_t, 16> fp_key0_, fp_key1_; // дві підключі -> 128-біт відбиток
    Backend crypto_;
    static constexpr double MAX_LOAD = 0.75;

    std::pair<uint64_t, uint64_t> fingerprint(const std::string& key) const {
        const uint8_t* p = reinterpret_cast<const uint8_t*>(key.data());
        return { siphash24(p, key.size(), fp_key0_.data()),
                 siphash24(p, key.size(), fp_key1_.data()) };
    }

    void maybe_rehash() {
        if (count_ <= (size_t)(MAX_LOAD * buckets_.size())) return;
        size_t newn = buckets_.size() * 2;
        std::vector<SecureNode*> nb(newn, nullptr);
        for (SecureNode* head : buckets_) {
            while (head) {
                SecureNode* next = head->next;
                size_t idx = head->fp0 % newn;
                head->next = nb[idx];
                nb[idx] = head;
                head = next;
            }
        }
        buckets_.swap(nb);
    }

public:
    explicit SecureTable(size_t num_buckets = 16, bool authenticated = false)
        : buckets_(num_buckets ? num_buckets : 1, nullptr),
          count_(0), next_counter_(0), crypto_(authenticated) {
        fill_random_bytes(fp_key0_.data(), fp_key0_.size());
        fill_random_bytes(fp_key1_.data(), fp_key1_.size());
        lock_mem(fp_key0_.data(), fp_key0_.size());
        lock_mem(fp_key1_.data(), fp_key1_.size());
    }

    SecureTable(const SecureTable&) = delete;
    SecureTable& operator=(const SecureTable&) = delete;

    ~SecureTable() {
        for (SecureNode* head : buckets_) {
            while (head) {
                SecureNode* next = head->next;
                wipe_node(*head);
                delete head;
                head = next;
            }
        }
        secure_wipe(fp_key0_.data(), fp_key0_.size());
        secure_wipe(fp_key1_.data(), fp_key1_.size());
        unlock_mem(fp_key0_.data(), fp_key0_.size());
        unlock_mem(fp_key1_.data(), fp_key1_.size());
    }

    bool authenticated() const { return crypto_.authenticated(); }

    void insert(const std::string& key, const std::string& value) {
        auto fp = fingerprint(key);
        size_t idx = fp.first % buckets_.size();
        for (SecureNode* n = buckets_[idx]; n; n = n->next) {
            if (n->fp0 == fp.first && n->fp1 == fp.second) {
                n->counter = next_counter_++;     // новий нонс при оновленні
                crypto_.encrypt(*n, value);
                return;
            }
        }
        SecureNode* node = new SecureNode();
        node->fp0 = fp.first; node->fp1 = fp.second;
        node->counter = next_counter_++;
        crypto_.encrypt(*node, value);
        node->next = buckets_[idx];
        buckets_[idx] = node;
        ++count_;
        maybe_rehash();
    }

    // Повертає true і дешифрує у out_value. У режимі AEAD кидає
    // std::runtime_error, якщо шифротекст підроблено.
    bool find(const std::string& key, std::string& out_value) const {
        auto fp = fingerprint(key);
        size_t idx = fp.first % buckets_.size();
        for (SecureNode* n = buckets_[idx]; n; n = n->next) {
            if (n->fp0 == fp.first && n->fp1 == fp.second) {
                out_value = crypto_.decrypt(*n);
                return true;
            }
        }
        return false;
    }

    bool erase(const std::string& key) {
        auto fp = fingerprint(key);
        size_t idx = fp.first % buckets_.size();
        SecureNode* prev = nullptr;
        for (SecureNode* n = buckets_[idx]; n; prev = n, n = n->next) {
            if (n->fp0 == fp.first && n->fp1 == fp.second) {
                if (prev) prev->next = n->next;
                else      buckets_[idx] = n->next;
                wipe_node(*n);
                delete n;
                --count_;
                return true;
            }
        }
        return false;
    }

    size_t size() const { return count_; }
    size_t bucket_count() const { return buckets_.size(); }
    double load_factor() const { return (double)count_ / buckets_.size(); }

    // Лише для демонстрації: сирий шифротекст значення
    const std::vector<uint8_t>* raw_bytes(const std::string& key) const {
        auto fp = fingerprint(key);
        size_t idx = fp.first % buckets_.size();
        for (SecureNode* n = buckets_[idx]; n; n = n->next)
            if (n->fp0 == fp.first && n->fp1 == fp.second) return &n->ciphertext;
        return nullptr;
    }
};

} // namespace sht

// Зручні псевдоніми у глобальному просторі імен
using SecureNode = sht::SecureNode;
using SecurityProtocol = sht::ManualBackend;            // зворотна сумісність назви
using SecureHashTable = sht::SecureTable<sht::ManualBackend>;
