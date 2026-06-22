cmake_minimum_required(VERSION 3.16)
project(HashTableSecurity LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Кожен .cpp напряму #include "protocol.cpp", тож кожна ціль — один файл.

# Тести
add_executable(test_runner test.cpp)

# Демо-застосунок "Secure Vault"
add_executable(app test_app.cpp)

# Бенчмарк (ручний ChaCha20 vs plaintext)
add_executable(benchmark benchmark.cpp)

# Порівняння з OpenSSL — лише якщо бібліотека доступна
find_package(OpenSSL)
if(OpenSSL_FOUND)
    add_executable(benchmark_openssl benchmark_openssl.cpp)
    target_link_libraries(benchmark_openssl PRIVATE OpenSSL::Crypto)
    message(STATUS "OpenSSL ${OPENSSL_VERSION} знайдено — ціль benchmark_openssl увімкнено")
else()
    message(STATUS "OpenSSL не знайдено — ціль benchmark_openssl пропущено")
endif()

# Реєструємо тести у CTest
enable_testing()
add_test(NAME unit_tests COMMAND test_runner)
