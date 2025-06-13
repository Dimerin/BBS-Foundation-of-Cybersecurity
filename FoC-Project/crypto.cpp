#include "crypto.h"

int gcm_encrypt(unsigned char *plaintext, int plaintext_len,
                unsigned char *aad, int aad_len,
                unsigned char *key,
                unsigned char *iv, int iv_len,
                unsigned char *&ciphertext,
                int& ciphertext_len,
                unsigned char *&tag,
                int tag_len)
{
  if(!plaintext || !key || !iv || !aad){
    cout<<"Error in gcm_encrypt"<<endl;
    return -1;
  }
  if(plaintext_len <= 0 || aad_len <= 0 || iv_len <= 0 || tag_len <= 0){
    cout<<"Error in lengths gcm"<<endl;
    return -1;
  }
	int len;
  int block_size = 0;
	EVP_CIPHER_CTX *ctx;
  ciphertext = new unsigned char[plaintext_len + AES128_BLOCK_SIZE];
  tag = new unsigned char[TAG_SIZE];
	ctx= EVP_CIPHER_CTX_new();
  if(!ctx){
    cout<<"Error in EVP_CIPHER_CTX_new"<<endl;
    delete [] ciphertext;
    delete [] tag;
    return -1;
  }
  if(ciphertext == NULL){
    cout<<"Error in ciphertext allocation"<<endl;
    EVP_CIPHER_CTX_free(ctx);
    delete [] tag;
    return -1;
  }
	if(!EVP_EncryptInit(ctx, EVP_aes_128_gcm(), key, iv)){
		cout <<"Error in EncryptInit"<<endl;
    EVP_CIPHER_CTX_free(ctx);
    delete [] ciphertext;
    delete [] tag;
    return -1;
	}
  for(int i = 0; i < aad_len; i += FRAGMENT_SIZE){
    block_size = i + FRAGMENT_SIZE > aad_len ? aad_len - i : FRAGMENT_SIZE;
    if(!EVP_EncryptUpdate(ctx, NULL, &len, aad + i, block_size)){
      cout<<"Error in EncryptUpdate"<<endl;
      EVP_CIPHER_CTX_free(ctx);
      delete [] ciphertext;
      delete [] tag;
      return -1;
    }
  }

	ciphertext_len = 0;
	for(int i = 0; i < plaintext_len; i+= FRAGMENT_SIZE){
		block_size = i + FRAGMENT_SIZE > plaintext_len ? plaintext_len - i : FRAGMENT_SIZE;
		if(EVP_EncryptUpdate(ctx, ciphertext+ciphertext_len, &len, plaintext+i, block_size)){
			ciphertext_len += len;
		}
		else{
			cout<<"Error in EncryptUpdate"<<endl;
      delete[] ciphertext;
      delete[] tag;
      EVP_CIPHER_CTX_free(ctx);
      return -1;
		}
	}
	if(!EVP_EncryptFinal(ctx, ciphertext +ciphertext_len, &len)){
		cout<<"Error in EncryptFinal"<<endl;
    delete[] ciphertext;
    delete[] tag;
    EVP_CIPHER_CTX_free(ctx);
    return -1;
	}
	ciphertext_len += len;
	if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, TAG_SIZE, tag)){
		cout<<"Error in EVP_CIPHER_CTX_ctrl"<<endl;
    delete[] ciphertext;
    delete[] tag;
    EVP_CIPHER_CTX_free(ctx);
    return -1;
	}
  tag_len = TAG_SIZE;
	EVP_CIPHER_CTX_free(ctx);
	return 1;
}

int gcm_decrypt(unsigned char *ciphertext, int ciphertext_len,
                unsigned char *aad, int aad_len,
                unsigned char *tag,
                int tag_len,
                unsigned char *key,
                unsigned char *iv, int iv_len,
                unsigned char *&plaintext,
                int& plaintext_len)
{
  if(!ciphertext || !key || !iv || !aad || !tag){
    cout<<"Error in gcm_decrypt"<<endl;
    return -1;
  }
  if(ciphertext_len <= 0 || aad_len <= 0 || iv_len <= 0 || tag_len <= 0){
    cout<<"Error in lengths gcm"<<endl;
    return -1;
  }
	int len;
  int block_size = 0;
	EVP_CIPHER_CTX *ctx;
  plaintext = new unsigned char[ciphertext_len];
  plaintext_len = 0;
	ctx = EVP_CIPHER_CTX_new();
  if(!ctx){
    cout<<"Error in EVP_CIPHER_CTX_new"<<endl;
    delete[] plaintext;
    return -1;
  }
	if(!EVP_DecryptInit(ctx, EVP_aes_128_gcm(), key, iv)){
		cout<<"Error in DecryptInit"<<endl;
    delete[] plaintext;
    EVP_CIPHER_CTX_free(ctx);
    return -1;
	}
  for(int i = 0; i < aad_len; i += FRAGMENT_SIZE){
    block_size = i + FRAGMENT_SIZE > aad_len ? aad_len - i : FRAGMENT_SIZE;
    if(!EVP_DecryptUpdate(ctx, NULL, &len, aad + i, block_size)){
      cout<<"Error in DecryptUpdate"<<endl;
      delete[] plaintext;
      EVP_CIPHER_CTX_free(ctx);
      return -1;
    }
  }
  
	for(int i = 0; i < ciphertext_len; i += FRAGMENT_SIZE){
		block_size = i + FRAGMENT_SIZE > ciphertext_len ? ciphertext_len - i : FRAGMENT_SIZE;
		if(EVP_DecryptUpdate(ctx, plaintext+plaintext_len, &len, ciphertext+i, block_size)){
		plaintext_len += len;
		}
		else{
			cout<<"Error in DecryptUpdate"<<endl;
      delete[] plaintext;
      EVP_CIPHER_CTX_free(ctx);
      return -1;
		}
	}
  if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, tag)){
		cout<<"Error TAG decrypt"<<endl;
    delete[] plaintext;
    EVP_CIPHER_CTX_free(ctx);
    return -1;
	}
	
	if(!EVP_DecryptFinal(ctx, plaintext+plaintext_len, &len)){
		cout<<"Error in DecryptFinal"<<endl;
    delete[] plaintext;
    EVP_CIPHER_CTX_free(ctx);
    return -1;
	}
	plaintext_len += len;
	EVP_CIPHER_CTX_free(ctx);
	return 1;
}


int aes_encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
  unsigned char *iv, unsigned char* ciphertext)
{
  EVP_CIPHER_CTX *ctx;

  int len;
  int ciphertext_len = 0;
  if(!plaintext || !key || !iv){
    cout<<"Error in aes_encrypt"<<endl;
    return -1;
  }

  /* Create and initialise the context */
  ctx = EVP_CIPHER_CTX_new();
  if(!ctx){
    cout<<"Error in EVP_CIPHER_CTX_new"<<endl;
    EVP_CIPHER_CTX_free(ctx);
  }
  // Encrypt init
  if(!EVP_EncryptInit(ctx, EVP_aes_128_cbc(), key, iv)){
    cout<<"Error in EncryptInit"<<endl;
  }

  for(int i = 0; i < plaintext_len; i+= FRAGMENT_SIZE){
      int block_size = i + FRAGMENT_SIZE > plaintext_len ? plaintext_len - i : FRAGMENT_SIZE;
      if(EVP_EncryptUpdate(ctx, ciphertext+ciphertext_len, &len, plaintext+i, block_size)){
         ciphertext_len += len;
      }
        else{
            cout<<"Error in EncryptUpdate"<<endl;
        }
  }

  //Encrypt Final. Finalize the encryption and adds the padding
  if(EVP_EncryptFinal(ctx, ciphertext +ciphertext_len, &len)){
    ciphertext_len += len;
  }
  else{
    cout<<"Error in EncryptFinal"<<endl;
    }

  EVP_CIPHER_CTX_free(ctx);

  return ciphertext_len;
}

int aes_decrypt(unsigned char* ciphertext, int ciphertext_len, unsigned char* key, unsigned char* iv, unsigned char* plaintext)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len = 0;

    ctx = EVP_CIPHER_CTX_new();

    if(!ctx){
        cout<<"Error in EVP_CIPHER_CTX_new"<<endl;
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    if(!EVP_DecryptInit(ctx, EVP_aes_128_cbc(), key, iv)){
        cout<<"Error in DecryptInit"<<endl;
         EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    for(int i = 0; i < ciphertext_len; i += FRAGMENT_SIZE){
         int block_size = i + FRAGMENT_SIZE > ciphertext_len ? ciphertext_len - i : FRAGMENT_SIZE;
         if(!EVP_DecryptUpdate(ctx, plaintext+plaintext_len, &len, ciphertext+i, block_size)){
            cout<<"Error in DecryptUpdate"<<endl;
            EVP_CIPHER_CTX_free(ctx);
            return -1;
         }
         plaintext_len  += len;
    }
    if(EVP_DecryptFinal(ctx, plaintext+plaintext_len, &len)){
        plaintext_len += len;
    }
    else {
        cout<<"Error in DecryptFinal"<<endl;
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}

int compute_hash_sha256(unsigned char* in_data,int in_data_len,unsigned char*& out_hash,unsigned int& out_hash_len){
   int ret=0;

   out_hash = (unsigned char *)malloc(EVP_MD_size(EVP_sha256()));
   if (out_hash == NULL){
      return -1;
   }

   EVP_MD_CTX *ctx;
   ctx = EVP_MD_CTX_new();
   if (!ctx){
      free(out_hash);
      return -1;
   }

   ret = EVP_DigestInit(ctx, EVP_sha256());
   if (ret != 1){
      EVP_MD_CTX_free(ctx);
      free(out_hash);
      return -1;
   }


   for(int i = 0; i < in_data_len; i += FRAGMENT_SIZE){
      int work_len = i + FRAGMENT_SIZE > in_data_len ? in_data_len - i : FRAGMENT_SIZE;
      ret = EVP_DigestUpdate(ctx, (unsigned char *)(in_data + i), work_len);
      if (ret != 1){
         EVP_MD_CTX_free(ctx);
         free(out_hash);
         return -1;
      }
   }

   ret = EVP_DigestFinal(ctx, out_hash, &out_hash_len);
   if (ret != 1){
      EVP_MD_CTX_free(ctx);
      free(out_hash);
      return -1;
   }

   EVP_MD_CTX_free(ctx);

  return SHA256_DIGEST_LENGTH;
}

bool RSA_encrypt(EVP_PKEY *pubkey, unsigned char *plaintext, int plaintext_len, unsigned char *&ciphertext, int& ciphertext_len, unsigned char*& iv, int& iv_len, unsigned char*& encrypted_key, int& encrypted_key_len){
    if(!pubkey){
      cout<<"Public Key not valid"<<endl;
      return false;
    }
    if(!plaintext){
      cout<<"Plaintext not valid"<<endl;
      return false;
    }
    if(plaintext_len <= 0){
      cout<<"Plaintext length not valid"<<endl;
      return false;
    }
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    encrypted_key_len = EVP_PKEY_size(pubkey);
    iv_len = EVP_CIPHER_iv_length(EVP_aes_128_cbc());
    encrypted_key = new unsigned char[encrypted_key_len];
    iv = new unsigned char[iv_len];
    if(!encrypted_key){
      cout<<"Error encrypted key"<<endl;
      return false;
    }
    if(!iv){
      cout<<"Error iv"<<endl;
      return false;
    }
    if(!ctx){
      cout<<"Error in EVP_PKEY_CTX_new"<<endl;
      EVP_CIPHER_CTX_free(ctx);
      return false;
    }
    if( plaintext_len > INT_MAX - AES128_BLOCK_SIZE){
      cout<<"Error overflow RSA_ENCRYPT"<<endl;
      delete iv;
      delete encrypted_key;
      EVP_CIPHER_CTX_free(ctx);
      return false;
    }
    ciphertext = new unsigned char[plaintext_len + AES128_BLOCK_SIZE];
    if(!ciphertext){
      cout<<"Error in ciphertext allocation"<<endl;
      delete iv;
      delete encrypted_key;
      EVP_CIPHER_CTX_free(ctx);
      return false;
    }
    if(!EVP_SealInit(ctx, EVP_aes_128_cbc(), &encrypted_key, &encrypted_key_len, iv, &pubkey, 1)){
      cout<<"Error in SealInit"<<endl;
      delete iv;
      delete ciphertext;
      delete encrypted_key;
      EVP_CIPHER_CTX_free(ctx);
      return false;
    }
    ciphertext_len = 0;
    int len;
    for(int i = 0; i < plaintext_len; i += FRAGMENT_SIZE){
      int block_size = i + FRAGMENT_SIZE > plaintext_len ? plaintext_len - i : FRAGMENT_SIZE;
      if(!EVP_SealUpdate(ctx, ciphertext + ciphertext_len, &len, plaintext + i, block_size)){
        cout<<"Error in SealUpdate"<<endl;
        delete iv;
        delete ciphertext;
        delete encrypted_key;
        EVP_CIPHER_CTX_free(ctx);
        return false;
      }
      ciphertext_len += len;
    }
    if(!EVP_SealFinal(ctx, ciphertext + ciphertext_len, &len)){
      cout<<"Error in SealFinal"<<endl;
      delete iv;
      delete ciphertext;
      delete encrypted_key;
      EVP_CIPHER_CTX_free(ctx);
      return false;
    }
    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return true;
}

bool RSA_decrypt(EVP_PKEY *privatekey, unsigned char *ciphertext, int ciphertext_len, unsigned char *&plaintext, int & plaintext_len, unsigned char* iv, int iv_len, unsigned char* encrypted_key, int encrypted_key_len){
    if(!privatekey){
      cout<<"Private Key not valid"<<endl;
      return false;
    }
    if(!ciphertext){
      cout<<"Ciphertext not valid"<<endl;
      return false;
    }
    if(ciphertext_len <= 0){
      cout<<"Ciphertext length not valid"<<endl;
      return false;
    }
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if(!ctx){
      cout<<"Error in EVP_PKEY_CTX_new"<<endl;
      EVP_CIPHER_CTX_free(ctx);
      return false;
    }
    if(encrypted_key_len > INT_MAX - AES128_BLOCK_SIZE){
      cout<<"Error overflow RSA_DECRYPT"<<endl;
      EVP_CIPHER_CTX_free(ctx);
      return false;
    }
    plaintext = new unsigned char[ciphertext_len];
    if(!plaintext){
      cout<<"Error in plaintext allocation"<<endl;
      EVP_CIPHER_CTX_free(ctx);
      return false;
    }
    int len;
    if(!EVP_OpenInit(ctx, EVP_aes_128_cbc(), encrypted_key, encrypted_key_len, iv, privatekey)){
      cout<<"Error in OpenInit"<<endl;
      delete plaintext;
      EVP_CIPHER_CTX_free(ctx);
      return false;
    }
    plaintext_len = 0;
    int block_size;
    for(int i = 0; i < ciphertext_len; i += FRAGMENT_SIZE){
      block_size = i + FRAGMENT_SIZE > ciphertext_len ? ciphertext_len - i : FRAGMENT_SIZE;
      if(!EVP_OpenUpdate(ctx, plaintext + plaintext_len, &len, ciphertext + i, block_size)){
        cout<<"Error in OpenUpdate"<<endl;
        delete plaintext;
        EVP_CIPHER_CTX_free(ctx);
        return false;
      }
      plaintext_len += len;
    }
    if(!EVP_OpenFinal(ctx, plaintext + plaintext_len, &len)){
      cout<<"Error in OpenFinal"<<endl;
      delete plaintext;
      EVP_CIPHER_CTX_free(ctx);
      return false;
    }
    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return true;
}


EVP_PKEY* read_key_from_file(string filename, bool is_public){
    EVP_PKEY* key = NULL;
    FILE* fp = fopen(filename.c_str(), "r");
    if(!fp){
      cout<<"Error in opening file"<<endl;
      return NULL;
    }
    if(is_public){
      key = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    }
    else{
      key = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    }
    if(!key){
      cout<<"Error in reading key"<<endl;
      fclose(fp);
      return NULL;
    }
    fclose(fp);
    return key;
}

DH *get_dh2048(void)
{
    static unsigned char dhp_2048[] = {
        0xEC, 0x65, 0x5A, 0x9F, 0xBF, 0xC3, 0xC7, 0xDA, 0x11, 0x25,
        0xA3, 0xDF, 0xE6, 0x31, 0xE5, 0xE2, 0x88, 0x55, 0x7F, 0x7B,
        0x00, 0xF4, 0xC8, 0x7E, 0xF0, 0xCB, 0x13, 0x16, 0xCA, 0xDB,
        0xFE, 0x69, 0x1E, 0x98, 0x1E, 0x76, 0x2B, 0x63, 0xC6, 0x4D,
        0xB3, 0x01, 0xF7, 0x22, 0xD6, 0xFB, 0x8A, 0x1E, 0x84, 0x54,
        0x28, 0x05, 0x04, 0x76, 0x4B, 0xAB, 0x5C, 0x7C, 0xF1, 0x16,
        0xE6, 0xD8, 0xCC, 0xFC, 0xAC, 0xB0, 0xEC, 0x1D, 0xA7, 0xD0,
        0x59, 0x4E, 0xC1, 0xFE, 0xE1, 0x54, 0x17, 0xCC, 0x20, 0x8B,
        0xD2, 0x8E, 0xFF, 0x11, 0xB4, 0x1E, 0x3A, 0xB8, 0x96, 0xD9,
        0xAA, 0x3C, 0x29, 0x10, 0x2B, 0xC2, 0x36, 0x11, 0xD1, 0xE2,
        0x3A, 0xFD, 0xE3, 0xE1, 0x67, 0x73, 0x54, 0x3D, 0xE5, 0xC5,
        0x0B, 0xC6, 0xF2, 0x3A, 0x4A, 0x78, 0x75, 0xBC, 0x59, 0x52,
        0x41, 0x8A, 0x20, 0xE4, 0xC2, 0x9F, 0xC1, 0x5B, 0x9B, 0xDA,
        0x64, 0x3E, 0xB2, 0x7D, 0x5E, 0xCF, 0x99, 0xBE, 0x16, 0xE0,
        0x00, 0x67, 0xE5, 0xEE, 0xB3, 0x57, 0xAE, 0x19, 0x15, 0x30,
        0xB3, 0x49, 0x96, 0x9A, 0xA6, 0xD2, 0x15, 0x04, 0x0C, 0x8E,
        0xC1, 0xB6, 0x9D, 0x7C, 0x6F, 0x8D, 0x0D, 0xBB, 0xF8, 0x1A,
        0x63, 0x88, 0xF0, 0x5B, 0xCC, 0xF0, 0xDF, 0xE0, 0xCC, 0x0C,
        0xD1, 0x40, 0xA2, 0x09, 0x85, 0xE5, 0xD7, 0x01, 0x66, 0x7A,
        0x80, 0xEE, 0xA0, 0x5D, 0x6E, 0xFE, 0xD2, 0x72, 0xEF, 0x3E,
        0xFD, 0x62, 0x76, 0xC0, 0xC5, 0xC2, 0x5E, 0x80, 0x47, 0x4E,
        0xE1, 0x7D, 0x18, 0x1A, 0xA2, 0x38, 0x36, 0xD2, 0xA1, 0xB2,
        0x01, 0xFE, 0x8E, 0x04, 0x3B, 0xB3, 0x18, 0xC8, 0x80, 0x86,
        0xF9, 0x31, 0x18, 0x5D, 0x91, 0xE6, 0x46, 0x8B, 0x62, 0x4A,
        0xB1, 0x2B, 0xD8, 0xB3, 0x72, 0x08, 0xDF, 0xF2, 0x1A, 0xD9,
        0x8B, 0xA9, 0x30, 0xB3, 0xF2, 0x1B
    };
    static unsigned char dhg_2048[] = {
        0x02
    };
    DH *dh = DH_new();
    BIGNUM *p, *g;

    if (dh == NULL)
        return NULL;
    p = BN_bin2bn(dhp_2048, sizeof(dhp_2048), NULL);
    g = BN_bin2bn(dhg_2048, sizeof(dhg_2048), NULL);
    if (p == NULL || g == NULL
            || !DH_set0_pqg(dh, p, NULL, g)) {
        DH_free(dh);
        BN_free(p);
        BN_free(g);
        return NULL;
    }
    return dh;
}

bool DH_private_key_generation(EVP_PKEY*& DH_key){
    EVP_PKEY* dh_params;
    DH* dh = get_dh2048();
    if(!dh){
        cout<<"Error in get_dh2048"<<endl;
        return false;
    }
    dh_params = EVP_PKEY_new();
    if(!dh_params){
      cout<<"Error in EVP_PKEY_new"<<endl;
      return false;
    }
    if(!EVP_PKEY_set1_DH(dh_params, dh)){
      cout<<"Error in EVP_PKEY_set1_DH"<<endl;
      EVP_PKEY_free(dh_params);
      return false;
    }
    DH_free(dh);
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(dh_params, NULL);
    if(!ctx){
      cout<<"Error in EVP_PKEY_CTX_new"<<endl;
      EVP_PKEY_free(dh_params);
      return false;
    }
    if(EVP_PKEY_keygen_init(ctx) <= 0){
      cout<<"Error in EVP_PKEY_keygen_init"<<endl;
      EVP_PKEY_CTX_free(ctx);
      EVP_PKEY_free(dh_params);
      return false;
    }

    EVP_PKEY* DH_private_key = NULL;
    if(EVP_PKEY_keygen(ctx, &DH_private_key) <= 0){
      cout<<"Error in EVP_PKEY_keygen"<<endl;
      EVP_PKEY_CTX_free(ctx);
      EVP_PKEY_free(dh_params);
      return false;
    }

    DH_key = DH_private_key;
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(dh_params);

    return true;

}

bool DH_key_derivation(unsigned char*& shared_secret,int& secretlen, EVP_PKEY* local_priv_key, EVP_PKEY* remote_pub_key){
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(local_priv_key, NULL);
    if(!ctx){
        cout<<"Error in EVP_PKEY_CTX_new"<<endl;
        return false;
    }

    if(EVP_PKEY_derive_init(ctx) <= 0){
        cout<<"Error in EVP_PKEY_derive_init"<<endl;
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    if(EVP_PKEY_derive_set_peer(ctx, remote_pub_key) <= 0){
        cout<<"Error in EVP_PKEY_derive_set_peer"<<endl;
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    size_t secret_len;
    if(EVP_PKEY_derive(ctx, NULL, &secret_len) <= 0){
        cout<<"Error in EVP_PKEY_derive"<<endl;
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    unsigned char* secret = new unsigned char[secret_len];
    if(EVP_PKEY_derive(ctx, secret, &secret_len) <= 0){
        cout<<"Error in EVP_PKEY_derive"<<endl;
        delete[] secret;
        EVP_PKEY_CTX_free(ctx);
        return false;
    }
    shared_secret = secret;
    secretlen = secret_len;
    EVP_PKEY_CTX_free(ctx);

    return true;
}



bool dh_pub_key_serialization(EVP_PKEY *dh_key, unsigned char *&plaintext_key, int &plaintext_len)
{
    BIO *bio;
    bio = BIO_new(BIO_s_mem());
    int ret;
    ret = PEM_write_bio_PUBKEY(bio, dh_key);
    if(ret != 1)
    {
        cout << "serialization error" << endl;
        BIO_free(bio);
        return false;
    }


   plaintext_len = BIO_ctrl_pending(bio); //return the length of BIO memory buffer
   plaintext_key = (unsigned char*)malloc(plaintext_len);
   ret = BIO_read(bio, plaintext_key, plaintext_len);
   
   if(ret != plaintext_len)
   {
      cout << "error bio_read: " << ret << endl;
      BIO_free(bio);
      return false;
   }

   BIO_free(bio);
   return true;

}

bool dh_pub_key_deserialization(EVP_PKEY *&dh_pub_key, unsigned char *plaintext_key, int plaintext_len)
{

    int ret;
    BIO *bio;
    bio = BIO_new(BIO_s_mem());
    ret = BIO_write(bio, plaintext_key, plaintext_len);
   
   if(ret != plaintext_len)
   {
      cout << "Error: "<< ret << endl;
      BIO_free(bio);
      return false;
   }

    dh_pub_key = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    if(dh_pub_key == NULL)
    {
        cout << "deserialization error" << endl;
        BIO_free(bio);
        return false;
    }

    BIO_free(bio);
    return true;

}


bool DHE_key_exchange(EVP_PKEY*& private_key, unsigned char* pre_shared_secret, unsigned char*& encrypted_pub, int& encrypted_len_pub,unsigned char*& DH_iv ){
    int len;
    unsigned char* pub_key;
    DH_iv = new unsigned char[AES128_BLOCK_SIZE];
    if(!DH_iv){
        cout<<"Error in IV allocation"<<endl;
        return false;
    }
    if(RAND_bytes(DH_iv, AES128_BLOCK_SIZE) == 0){
                    cout << "Error generating the IV" << endl;
                    return false;
    }
    dh_pub_key_serialization(private_key, pub_key, len);
    //cout << "pub_key: " << pub_key << endl;
    if(!pub_key){
        cout<<"Error in DH_retrieve_pub_key"<<endl;
        return false;
    }
    encrypted_pub = new unsigned char[len+BLOCK_SIZE];
    encrypted_len_pub = aes_encrypt(pub_key, len, pre_shared_secret, DH_iv, encrypted_pub);
    if(encrypted_len_pub == -1){
        cout<<"Error in aes_encrypt"<<endl;
        delete pub_key;
        return false;
    }
    delete pub_key;
    return true;
}

bool DHE_create_session_key(EVP_PKEY* private_key, EVP_PKEY* public_key, int public_key_len, unsigned char*& session_key,unsigned int& session_key_length){
    if(!private_key){
        cout<<"Private key not valid"<<endl;
        return false;
    }
    if(!public_key){
        cout<<"Public key not valid"<<endl;
        return false;
    }
    if(public_key_len <= 0){
        cout<<"Public key length not valid"<<endl;
        return false;
    }
    unsigned char* shared_secret;
    int shared_secret_len;
    if(!DH_key_derivation(shared_secret, shared_secret_len, private_key, public_key)){
        cout<<"Error in DH_key_derivation"<<endl;
        return false;
    }
    int ret;
    ret = compute_hash_sha256(shared_secret, shared_secret_len, session_key, session_key_length);
    if(ret == -1){
        cout<<"Error in compute_hash_sha256"<<endl;
        return false;
    }
    delete shared_secret;
    return true;
}