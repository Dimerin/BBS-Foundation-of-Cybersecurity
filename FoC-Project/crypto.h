#include <iostream> 
#include <string>
#include <stdio.h> 
#include <limits.h> 
#include <string.h> 
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <iomanip>
#include "constants.h"
#include <sys/stat.h>
#include <sys/types.h>

using namespace std;

int gcm_encrypt(unsigned char *plaintext, int plaintext_len,
                unsigned char *aad, int aad_len,
                unsigned char *key,
                unsigned char *iv, int iv_len,
                unsigned char *&ciphertext,
                int& ciphertext_len,
                unsigned char *&tag,
                int tag_len);

int gcm_decrypt(unsigned char *ciphertext, int ciphertext_len,
                unsigned char *aad, int aad_len,
                unsigned char *tag,
                int tag_len,
                unsigned char *key,
                unsigned char *iv, int iv_len,
                unsigned char *&plaintext,
                int& plaintext_len);


int aes_encrypt(unsigned char *plaintext,
                int plaintext_len,
                unsigned char *key,
                unsigned char *iv,
                unsigned char *ciphertext);

int aes_decrypt(unsigned char* ciphertext,
                int ciphertext_len,
                unsigned char* key,
                unsigned char* iv,
                unsigned char* plaintext);

int compute_hash_sha256(unsigned char* in_data,
                        int in_data_len,
                        unsigned char*& out_hash,
                        unsigned int& out_hash_len);

bool RSA_encrypt(EVP_PKEY *pubkey,
                unsigned char *plaintext,
                int plaintext_len,
                unsigned char *&ciphertext,
                int& ciphertext_len,
                unsigned char*& iv,
                int& iv_len,
                unsigned char*& encrypted_key,
                int& encrypted_key_len);

bool RSA_decrypt(EVP_PKEY *privatekey,
                unsigned char *ciphertext,
                int ciphertext_len,
                unsigned char *&plaintext,
                int & plaintext_len,
                unsigned char* iv,
                int iv_len,
                unsigned char* encrypted_key,
                int encrypted_key_len);
            
EVP_PKEY* read_key_from_file(string filename,
                            bool is_public);

bool DH_private_key_generation(EVP_PKEY *&privkey);

bool DH_key_derivation(unsigned char *&key,
                        int &key_len,
                        EVP_PKEY *privkey,
                        EVP_PKEY *peerkey);

bool DHE_key_exchange(EVP_PKEY*& private_key,
                      unsigned char* pre_shared_secret,
                      unsigned char*& encrypted_pub,
                      int& encrypted_len_pub,
                      unsigned char*& iv);

bool DHE_create_session_key(EVP_PKEY* private_key,
                            EVP_PKEY* public_key,
                            int public_key_len,
                            unsigned char*& session_key,
                            unsigned int& session_key_length);

bool dh_pub_key_serialization(EVP_PKEY* pub_key,
                              unsigned char*& buffer,
                              int& len);

bool dh_pub_key_deserialization(EVP_PKEY*& pub_key,
                                unsigned char* buffer,
                                int len);



