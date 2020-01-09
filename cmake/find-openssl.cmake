set(OPENSSL_ROOT_DIR ${EXTERNAL_DIR})

find_package(OpenSSL)

file( GLOB OPENSSL_SSL_DLL "${EXTERNAL_DIR}/bin/libssl-*.dll")
file( GLOB OPENSSL_CRYPTO_DLL "${EXTERNAL_DIR}/bin/libcrypto-*.dll")

message("OpenSSL DLLs ${OPENSSL_SSL_DLL} ${OPENSSL_CRYPTO_DLL}")
