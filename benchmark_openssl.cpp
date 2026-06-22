// Порівняння: ручний ChaCha20 (protocol.hpp) vs OpenSSL ChaCha20
// (protocol_openssl.hpp) vs plaintext std::unordered_map.
// Компіляція:  g++ -std=c++17 -O2 benchmark_openssl.cpp -o benchmark_openssl -lcrypto
#include <iostream>
#include <vector>
#include <string>
#include <unordered_map>
#include <chrono>
#include <iomanip>
#include <cstdint>

#include <openssl/evp.h>
#include <openssl/rand.h>

using namespace std;
using namespace std::chrono;

#include "protocol.hpp"          // ручний бекенд + ::SecureHashTable
#include "protocol_openssl.hpp"  // ossl::SecureHashTable

struct Timer {
    high_resolution_clock::time_point t0{high_resolution_clock::now()};
    double ms() const {
        return duration_cast<duration<double, milli>>(
                   high_resolution_clock::now() - t0).count();
    }
};

static volatile size_t g_sink = 0;

template <class Table>
static void bench_table(Table& table, const vector<string>& keys,
                        const vector<string>& values, double& ins, double& fnd) {
    int N = (int)keys.size();
    { Timer t; for (int i = 0; i < N; ++i) table.insert(keys[i], values[i]); ins = t.ms(); }
    { string out; Timer t;
      for (int i = 0; i < N; ++i) { table.find(keys[i], out); g_sink += out.size(); }
      fnd = t.ms(); }
}

static void openssl_chacha(const uint8_t key[32], const uint8_t iv[16],
                           uint8_t* data, int len) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int outl = 0, tmpl = 0;
    EVP_EncryptInit_ex(ctx, EVP_chacha20(), nullptr, key, iv);
    EVP_EncryptUpdate(ctx, data, &outl, data, len);
    EVP_EncryptFinal_ex(ctx, data + outl, &tmpl);
    EVP_CIPHER_CTX_free(ctx);
}

int main() {
    const int N = 100000;
    vector<string> keys(N), values(N);
    for (int i = 0; i < N; ++i) {
        keys[i]   = "key_" + to_string(i);
        values[i] = "secret_value_payload_" + to_string(i * 7);
    }

    cout << "============================================================\n";
    cout << " Порівняння реалізацій (записів: " << N << ")\n";
    cout << "============================================================\n\n";
    cout << fixed << setprecision(2);

    double p_ins, p_fnd;
    {
        unordered_map<string, string> plain; plain.reserve(N);
        { Timer t; for (int i = 0; i < N; ++i) plain[keys[i]] = values[i]; p_ins = t.ms(); }
        { Timer t; for (int i = 0; i < N; ++i) g_sink += plain[keys[i]].size(); p_fnd = t.ms(); }
    }

    double m_ins, m_fnd;
    { ::SecureHashTable t(16); bench_table(t, keys, values, m_ins, m_fnd); }

    double o_ins, o_fnd;
    { ossl::SecureHashTable t(16); bench_table(t, keys, values, o_ins, o_fnd); }

    auto row = [&](const char* name, double ins, double fnd) {
        cout << left << setw(26) << name << right
             << " insert: " << setw(8) << ins << " ms"
             << "   find: " << setw(8) << fnd << " ms\n";
    };

    cout << "--- Операції таблиці ---\n";
    row("unordered_map (plain)", p_ins, p_fnd);
    row("SecureHT (ручний)",     m_ins, m_fnd);
    row("SecureHT (OpenSSL)",    o_ins, o_fnd);
    cout << "\nfind vs plaintext:  ручний x" << (m_fnd / p_fnd)
         << ",  OpenSSL x" << (o_fnd / p_fnd) << "\n";
    cout << "OpenSSL vs ручний (find): x" << (m_fnd / o_fnd)
         << " (>1 = OpenSSL швидше)\n";

    cout << "\n--- Пропускна здатність ChaCha20 (256 МБ) ---\n";
    const size_t BLOB = 256u * 1024 * 1024;
    const double MB = BLOB / (1024.0 * 1024.0);
    uint8_t key[32], iv[16], nonce[12] = {0};
    RAND_bytes(key, 32); RAND_bytes(iv, 16);

    {
        vector<uint8_t> buf(BLOB, 0x41);
        Timer t; sht::chacha::xor_stream(key, nonce, buf.data(), buf.size());
        double ms = t.ms();
        cout << "Ручний:  " << setw(8) << ms << " ms  -> " << (MB / (ms / 1000.0)) << " МБ/с\n";
        g_sink += buf[0];
    }
    {
        vector<uint8_t> buf(BLOB, 0x41);
        Timer t; openssl_chacha(key, iv, buf.data(), (int)buf.size());
        double ms = t.ms();
        cout << "OpenSSL: " << setw(8) << ms << " ms  -> " << (MB / (ms / 1000.0)) << " МБ/с\n";
        g_sink += buf[0];
    }

    {
        ossl::SecureHashTable t(16);
        t.insert("k", "round-trip-value");
        string out;
        bool ok = t.find("k", out) && out == "round-trip-value";
        const vector<uint8_t>* raw = t.raw_bytes("k");
        bool enc = raw && string(raw->begin(), raw->end()) != "round-trip-value";
        cout << "\nКоректність OpenSSL-варіанту: round-trip "
             << (ok ? "OK" : "FAIL") << ", at-rest "
             << (enc ? "зашифровано" : "ВІДКРИТО!") << "\n";
    }

    g_sink += 1;
    return 0;
}
