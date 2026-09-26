#include "crypto.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

void sha256_hex(const char *data, char output[HASH_HEX_SIZE])
{
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char *)data, strlen(data), digest);
    bytes_to_hex(digest, SHA256_DIGEST_LENGTH, output);
}

EVP_PKEY *generate_key_pair(void)
{
    EVP_PKEY *key = EVP_EC_gen(SIGNATURE_CURVE);
    if (key == NULL) {
        fprintf(stderr, "ERROR: could not generate a %s key pair\n", SIGNATURE_CURVE);
    }
    return key;
}

/*
 * The private key is written encrypted with AES-256 under the librarian's
 * passphrase, and the file is created with 0600 permissions so no other
 * user on the machine can read it.
 */
bool save_key_pair(EVP_PKEY *key, const char *private_path, const char *public_path, const char *passphrase)
{
    int private_fd = open(private_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (private_fd < 0) {
        fprintf(stderr, "ERROR: cannot write %s (%s)\n", private_path, strerror(errno));
        return false;
    }
    FILE *private_file = fdopen(private_fd, "w");
    if (private_file == NULL) {
        fprintf(stderr, "ERROR: cannot write %s (%s)\n", private_path, strerror(errno));
        close(private_fd);
        return false;
    }
    int written = PEM_write_PrivateKey(private_file, key, EVP_aes_256_cbc(),
                                       (const unsigned char *)passphrase, (int)strlen(passphrase),
                                       NULL, NULL);
    fclose(private_file);
    if (written != 1) {
        fprintf(stderr, "ERROR: could not encrypt and save the private key\n");
        return false;
    }

    FILE *public_file = fopen(public_path, "w");
    if (public_file == NULL) {
        fprintf(stderr, "ERROR: cannot write %s (%s)\n", public_path, strerror(errno));
        return false;
    }
    written = PEM_write_PUBKEY(public_file, key);
    fclose(public_file);
    if (written != 1) {
        fprintf(stderr, "ERROR: could not save the public key\n");
        return false;
    }
    return true;
}

EVP_PKEY *load_private_key(const char *path, const char *passphrase)
{
    FILE *file = fopen(path, "r");
    if (file == NULL) {
        fprintf(stderr, "ERROR: cannot open %s (%s)\n", path, strerror(errno));
        return NULL;
    }
    EVP_PKEY *key = PEM_read_PrivateKey(file, NULL, NULL, (void *)passphrase);
    fclose(file);
    return key;
}

EVP_PKEY *load_public_key(const char *path)
{
    FILE *file = fopen(path, "r");
    if (file == NULL) {
        fprintf(stderr, "ERROR: cannot open %s (%s)\n", path, strerror(errno));
        return NULL;
    }
    EVP_PKEY *key = PEM_read_PUBKEY(file, NULL, NULL, NULL);
    fclose(file);
    if (key == NULL) {
        fprintf(stderr, "ERROR: %s does not contain a valid public key\n", path);
    }
    return key;
}

/*
 * ECDSA over SHA-256. The signature is DER encoded, so its length varies
 * between signatures; on secp256k1 it is never more than 72 bytes.
 */
bool sign_data(EVP_PKEY *private_key, const char *data,
               unsigned char signature[MAX_SIGNATURE_SIZE], unsigned int *signature_len)
{
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    size_t length = MAX_SIGNATURE_SIZE;

    bool signed_ok = context != NULL
        && EVP_DigestSignInit(context, NULL, EVP_sha256(), NULL, private_key) == 1
        && EVP_DigestSign(context, signature, &length, (const unsigned char *)data, strlen(data)) == 1;

    EVP_MD_CTX_free(context);
    if (signed_ok) {
        *signature_len = (unsigned int)length;
    }
    return signed_ok;
}

bool verify_signature(EVP_PKEY *public_key, const char *data,
                      const unsigned char *signature, unsigned int signature_len)
{
    EVP_MD_CTX *context = EVP_MD_CTX_new();

    bool verified = context != NULL
        && EVP_DigestVerifyInit(context, NULL, EVP_sha256(), NULL, public_key) == 1
        && EVP_DigestVerify(context, signature, signature_len, (const unsigned char *)data, strlen(data)) == 1;

    EVP_MD_CTX_free(context);
    return verified;
}

void bytes_to_hex(const unsigned char *bytes, size_t length, char *hex)
{
    for (size_t i = 0; i < length; i++) {
        sprintf(hex + i * 2, "%02x", bytes[i]);
    }
    hex[length * 2] = '\0';
}

/* Returns the number of bytes decoded, or -1 if hex is not valid hexadecimal. */
int hex_to_bytes(const char *hex, unsigned char *bytes, size_t max_length)
{
    size_t hex_length = strlen(hex);
    if (hex_length % 2 != 0 || hex_length / 2 > max_length) {
        return -1;
    }

    for (size_t i = 0; i < hex_length / 2; i++) {
        const char *pair = hex + i * 2;
        if (!isxdigit((unsigned char)pair[0]) || !isxdigit((unsigned char)pair[1])) {
            return -1;
        }
        sscanf(pair, "%2hhx", &bytes[i]);
    }
    return (int)(hex_length / 2);
}
