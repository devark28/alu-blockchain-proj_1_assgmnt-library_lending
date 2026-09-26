#ifndef CRYPTO_H
#define CRYPTO_H

#include <openssl/evp.h>
#include <stdbool.h>
#include <stddef.h>

#define HASH_HEX_SIZE 65
#define MAX_SIGNATURE_SIZE 72
#define SIGNATURE_CURVE "secp256k1"

void sha256_hex(const char *data, char output[HASH_HEX_SIZE]);

EVP_PKEY *generate_key_pair(void);
bool save_key_pair(EVP_PKEY *key, const char *private_path, const char *public_path, const char *passphrase);
EVP_PKEY *load_private_key(const char *path, const char *passphrase);
EVP_PKEY *load_public_key(const char *path);

bool sign_data(EVP_PKEY *private_key, const char *data,
               unsigned char signature[MAX_SIGNATURE_SIZE], unsigned int *signature_len);
bool verify_signature(EVP_PKEY *public_key, const char *data,
                      const unsigned char *signature, unsigned int signature_len);

void bytes_to_hex(const unsigned char *bytes, size_t length, char *hex);
int hex_to_bytes(const char *hex, unsigned char *bytes, size_t max_length);

#endif
