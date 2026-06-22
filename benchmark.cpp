#include <iostream>
#include <vector>
#include <string>
#include <unordered_map>
#include <chrono>
#include <iomanip>
#include <cstdint>
#include <functional>

using namespace std;
using namespace std::chrono;

#include "protocol.cpp"

// Простий таймер
struct Timer {
    high_resolution_clock::time_point t0;
    Timer() : t0(high_resolution_clock::now()) {}
    double ms() const {
        return duration_cast<duration<double, milli>>(
                   high_resolution_clock::now() - t0).count();
    }
};

// Глобальний "стік", щоб компілятор не викинув корисну роботу
static volatile size_t g_sink = 0;

int main() {
    const int N = 100000; // кількість записів

    // Заздалегідь готуємо ключі та значення (поза вимірюваннями)
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

    // ---------- Plaintext: std::unordered_map ----------
    unordered_map<string, string> plain;
    plain.reserve(N);

    double plain_insert, plain_find;
    {
        Timer t;
        for (int i = 0; i < N; ++i) plain[keys[i]] = values[i];
        plain_insert = t.ms();
    }
    {
        Timer t;
        for (int i = 0; i < N; ++i) g_sink += plain[keys[i]].size();
        plain_find = t.ms();
    }

    // ---------- Захищена: SecureHashTable ----------
    SecureHashTable secure(N * 2); // достатньо бакетів, щоб уникнути довгих ланцюжків

    double secure_insert, secure_find;
    {
        Timer t;
        for (int i = 0; i < N; ++i) secure.insert(keys[i], values[i]);
        secure_insert = t.ms();
    }
    {
        string out;
        Timer t;
        for (int i = 0; i < N; ++i) {
            secure.find(keys[i], out);
            g_sink += out.size();
        }
        secure_find = t.ms();
    }

    auto row = [&](const char* name, double ins, double fnd) {
        cout << left << setw(22) << name
             << " insert: " << right << setw(8) << ins << " ms"
             << "   find: " << setw(8) << fnd << " ms"
             << "   (" << setw(8) << (N / (fnd / 1000.0)) / 1e6
             << " M ops/s find)\n";
    };

    cout << "--- Операції таблиці ---\n";
    row("unordered_map", plain_insert, plain_find);
    row("SecureHashTable",  secure_insert, secure_find);
    cout << "\nЦіна безпеки (find):   x"
         << (secure_find / plain_find) << " повільніше\n";
    cout << "Ціна безпеки (insert): x"
         << (secure_insert / plain_insert) << " повільніше\n";

    // ---------- Пропускна здатність ChaCha20 ----------
    cout << "\n--- Пропускна здатність ChaCha20 ---\n";
    SecurityProtocol crypto;
    SecureNode node;
    const size_t BLOB = 64 * 1024 * 1024; // 64 МБ
    string blob(BLOB, 'A');
    {
        Timer t;
        crypto.encrypt(&node, blob);          // шифрування 64 МБ
        double enc_ms = t.ms();
        double mbps = (BLOB / (1024.0 * 1024.0)) / (enc_ms / 1000.0);
        cout << "Шифрування 64 МБ: " << enc_ms << " ms  -> "
             << mbps << " МБ/с\n";
        crypto.secure_wipe(&node);
    }

    g_sink += 1; // використовуємо стік
    return 0;
}
