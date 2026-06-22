#include <iostream>
#include <vector>
#include <string>
#include <unordered_map>
#include <chrono>
#include <iomanip>
#include <cstdint>

using namespace std;
using namespace std::chrono;

#include "protocol.hpp"

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
                        const vector<string>& values,
                        double& ins, double& fnd) {
    int N = (int)keys.size();
    { Timer t; for (int i = 0; i < N; ++i) table.insert(keys[i], values[i]); ins = t.ms(); }
    { string out; Timer t;
      for (int i = 0; i < N; ++i) { table.find(keys[i], out); g_sink += out.size(); }
      fnd = t.ms(); }
}

int main() {
    const int N = 100000;
    vector<string> keys(N), values(N);
    for (int i = 0; i < N; ++i) {
        keys[i]   = "key_" + to_string(i);
        values[i] = "secret_value_payload_" + to_string(i * 7);
    }

    cout << "============================================================\n";
    cout << " Бенчмарк: SecureHashTable (ChaCha20) vs std::unordered_map\n";
    cout << " Записів: " << N << "\n";
    cout << "============================================================\n\n";
    cout << fixed << setprecision(2);

    // --- plaintext ---
    double p_ins, p_fnd;
    {
        unordered_map<string, string> plain; plain.reserve(N);
        { Timer t; for (int i = 0; i < N; ++i) plain[keys[i]] = values[i]; p_ins = t.ms(); }
        { Timer t; for (int i = 0; i < N; ++i) g_sink += plain[keys[i]].size(); p_fnd = t.ms(); }
    }

    // --- захищена (ChaCha20) ---
    double s_ins, s_fnd;
    { SecureHashTable secure(16); bench_table(secure, keys, values, s_ins, s_fnd); }

    // --- захищена з автентифікацією (ChaCha20-Poly1305) ---
    double a_ins, a_fnd;
    { SecureHashTable secure(16, /*authenticated=*/true); bench_table(secure, keys, values, a_ins, a_fnd); }

    auto row = [&](const char* name, double ins, double fnd) {
        cout << left << setw(28) << name << right
             << " insert: " << setw(8) << ins << " ms"
             << "   find: " << setw(8) << fnd << " ms\n";
    };

    cout << "--- Операції таблиці ---\n";
    row("unordered_map (plaintext)", p_ins, p_fnd);
    row("SecureHashTable",           s_ins, s_fnd);
    row("SecureHashTable + AEAD",    a_ins, a_fnd);
    cout << "\nЦіна безпеки (find):   x" << (s_fnd / p_fnd) << " (ChaCha20), x"
         << (a_fnd / p_fnd) << " (з AEAD)\n";

    // --- Пропускна здатність ChaCha20 ---
    cout << "\n--- Пропускна здатність ChaCha20 ---\n";
    const size_t BLOB = 64 * 1024 * 1024;
    const double MB = BLOB / (1024.0 * 1024.0);
    uint8_t key[32], nonce[12] = {0};
    for (int i = 0; i < 32; ++i) key[i] = (uint8_t)i;
    vector<uint8_t> buf(BLOB, 0x41);
    {
        Timer t;
        sht::chacha::xor_stream(key, nonce, buf.data(), buf.size());
        double ms = t.ms();
        cout << "Шифрування 64 МБ: " << ms << " ms  -> " << (MB / (ms / 1000.0)) << " МБ/с\n";
        g_sink += buf[0];
    }

    g_sink += 1;
    return 0;
}
