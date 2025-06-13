#include "utility.h"


string byte_to_hex(unsigned char* hash) {
   stringstream ss;
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << hex << setw(2) << setfill('0') << (int)hash[i];
    }
    return ss.str();
}


unsigned char* from_string_to_unsigned_char(string str){
    unsigned char* res = new unsigned char[str.length() + 1];
    std::string::size_type i;
    for(i = 0; i < str.length(); i++){
        res[i] = str[i];
    }
    res[i] = '\0';
    return res;
}

bool send_RSA_message(int sd,EVP_PKEY* key,unsigned char* message, int message_len){
    unsigned char* ciphertext;
    int ciphertext_len;
    unsigned char* iv;
    int iv_len,encrypted_key_len;
    unsigned char* encrypted_key;
    int ret;
   
    if(!RSA_encrypt(key, message, message_len, ciphertext, ciphertext_len, iv, iv_len, encrypted_key, encrypted_key_len)){
        cout << "Error RSA encrypting" << endl;
        delete[] ciphertext;
        delete[] iv;
        delete[] encrypted_key;
        return false;
    }
    int ciphertext_size = htonl(ciphertext_len); 
    ret = send(sd, &ciphertext_size, sizeof(ciphertext_size), 0);
    if(ret < 0){
        cout << "Error sending the ciphertext size" << endl;
        delete[] ciphertext;
        delete[] encrypted_key;
        delete[] iv;
        return false;
    }
    ret = send(sd, ciphertext, ciphertext_len,0);
    //cout << ciphertext_len << endl;
    if(ret < 0){
        cout << "Error sending the ciphertext" << endl;
        delete[] ciphertext;
        delete[] encrypted_key;
        delete[] iv;
        return false;
    }
    ret = send(sd, encrypted_key, encrypted_key_len,0);
    //cout << encrypted_key_len << endl;
    if(ret < 0){
        cout << "Error sending the encrypted key" << endl;
        delete[] ciphertext;
        delete[] encrypted_key;
        delete[] iv;
        return false;
    }
    ret = send(sd, iv, iv_len,0);
    //cout << iv_len << endl;
    if(ret < 0){
        cout << "Error sending the iv" << endl;
        delete[] ciphertext;
        delete[] encrypted_key;
        delete[] iv;
        return false;
    }
    //cout << "Message sent" << endl;
    delete[] ciphertext;
    delete[] encrypted_key;
    delete[] iv;
    return true;
}

bool receive_RSA_message(int sd,EVP_PKEY* key, unsigned char*& message, int& message_len){
    unsigned char* ciphertext,*iv,*encrypted_key;
    int ciphertext_len,iv_len,encrypted_key_len,ret;
    iv_len = BLOCK_SIZE;
    encrypted_key_len = RSA_KEY_SIZE;
    iv = new unsigned char[iv_len];
    
    encrypted_key = new unsigned char[encrypted_key_len];
    int ciphertext_size;
    ret = recv(sd, &ciphertext_size, sizeof(ciphertext_size), 0);
    if(ret < 0){
        cout << "Error receiving the ciphertext size" << endl;
        return false;
    }
    ciphertext_len = ntohl(ciphertext_size); 
    ciphertext = new unsigned char[ciphertext_len];
    ret = recv(sd, ciphertext, ciphertext_len, 0);
    //cout << ciphertext_len<< endl;
    if(ret < 0){
        cout << "Error receiving the ciphertext" << endl;
        delete[] ciphertext;
        delete[] encrypted_key;
        delete[] iv;
        return false;
    }
    ret = recv(sd, encrypted_key, encrypted_key_len,0);
    //cout << encrypted_key_len<< endl;
    if(ret < 0){
        cout << "Error receiving the encrypted key" << endl;
        delete[] ciphertext;
        delete[] encrypted_key;
        delete[] iv;
        return false;
    }
    ret = recv(sd, iv, iv_len,0);
    //cout << iv_len << endl;
    if(ret < 0){
        cout << "Error receiving the iv" << endl;
        delete[] ciphertext;
        delete[] encrypted_key;
        delete[] iv;
        return false;
    }
    if(!RSA_decrypt(key, ciphertext, ciphertext_len, message, message_len, iv, iv_len, encrypted_key, encrypted_key_len)){
        cout << "Error RSA decrypting" << endl;
        delete[] ciphertext;
        delete[] encrypted_key;
        delete[] iv;
        return false;
    }
    message_len = ciphertext_len;

    delete[] ciphertext;
    delete[] encrypted_key;
    delete[] iv;
    return true;
}

bool send_public_key_DH(int fd, unsigned char* ciphertext, int ciphertext_len, unsigned char* iv){
    int ret;
    ret = send(fd, iv, AES128_BLOCK_SIZE,0);
    if(ret < 0){
        cout << "Error sending the IV" << endl;
        return false;
    }
    uint32_t ciphertext_size = htonl(ciphertext_len);
    ret = send(fd, &ciphertext_size, sizeof(ciphertext_size),0);
    if(ret < 0){
        cout << "Error sending the ciphertext size" << endl;
        return false;
    }
    ret = send(fd, ciphertext, ciphertext_len,0);
    if(ret < 0){
        cout << "Error sending the ciphertext" << endl;
        return false;
    }
    //cout<< "Public key sent" << endl;
    return true;
}

bool receive_public_key_DH(int fd, unsigned char*& ciphertext, int& ciphertext_len, unsigned char*& iv){
    int ret;
    iv = new unsigned char[AES128_BLOCK_SIZE];
    ret = recv(fd, iv, AES128_BLOCK_SIZE, 0);
    if(ret < 0){
        cout << "Error receiving the IV" << endl;
        return false;
    }
    ret = recv(fd, &ciphertext_len, sizeof(uint32_t), 0);
    if(ret < 0){
        cout << "Error receiving the ciphertext size" << endl;
        return false;
    }
    ciphertext_len = ntohl(ciphertext_len);
    ciphertext = new unsigned char[ciphertext_len];
    ret = recv(fd, ciphertext, ciphertext_len, 0);
    if(ret < 0){
        cout << "Error receiving the ciphertext" << endl;
        delete[] ciphertext;
        return false;
    }
    //cout << "Public key received" << endl;
    return true;
}
bool send_message_in_clear(int fd, unsigned char* message, int message_len){
    int ret;
    uint32_t message_size = htonl(message_len);
    ret = send(fd, &message_size, sizeof(message_size),0);
    if(ret < 0){
        cout << "Error sending the message size" << endl;
        return false;
    }
    ret = send(fd, message, message_len,0);
    if(ret < 0){
        cout << "Error sending the message" << endl;
        return false;
    }
    //cout<< "Message sent" << endl;
    return true;
}


bool send_encrypted_message(int fd, unsigned char* message, int message_len, unsigned char* key, unsigned char* iv){
    unsigned char* ciphertext = new unsigned char[message_len + BLOCK_SIZE];
    int ciphertext_len;
    int ret;
    ret = aes_encrypt(message, message_len, key, iv, ciphertext);
    if(ret == -1){
        cout << "Error encrypting the message" << endl;
        return false;
    }else {
        ciphertext_len = ret;
    }
    uint32_t message_len_net = htonl(ciphertext_len);
    ret = send(fd, &message_len_net, sizeof(uint32_t), 0);
    if(ret < 0){
        cout << "Error sending the message size" << endl;
        return false;
    }
    ret = send(fd, ciphertext, ciphertext_len, 0);
    if(ret < 0){
        cout << "Error sending the message" << endl;
        return false;
    }
    delete[] ciphertext;
    return true;
}

bool receive_encrypted_message(int fd, unsigned char*& message, int& message_len, unsigned char* key, unsigned char* iv){
    int ret;
    uint32_t message_len_net;
    ret = recv(fd, &message_len_net, sizeof(uint32_t), 0);
    if(ret < 0){
        cout << "Error receiving the message size" << endl;
        return false;
    }
    message_len = ntohl(message_len_net);
    message = new unsigned char[message_len];
    ret = recv(fd, message, message_len, 0);
    if(ret < 0){
        cout << "Error receiving the message" << endl;
        delete[] message;
        return false;
    }
    unsigned char* plaintext = new unsigned char[message_len];
    ret = aes_decrypt(message, message_len, key, iv, plaintext);
    if(ret == -1){
        cout << "Error decrypting the message" << endl;
        delete[] message;
        delete[] plaintext;
        return false;
    }else {
        message_len = ret;
        delete[] message;
        message = plaintext;
    }
    return true;
}


bool send_auth_and_encrypted_message(int fd, network_message message, unsigned char* key){
    //send(fd,(unsigned char*)"ok", 2, 0);
    unsigned char* iv = new unsigned char[IV_GCM];
    int ret;
    if(RAND_bytes(iv, IV_GCM) == 0){
        cout << "Error generating the IV" << endl;
        return false;
    }
    ret = send(fd, iv, IV_GCM, 0);
    //cout << "IV: " << iv << endl;
    //cout << "IV len: " << strlen((char*)iv) << endl;
    if(ret < 0){
        cout << "Error sending the IV" << endl;
        return false;
    }
    
    string str;
    if(!from_network_message_to_string(message, str)){
        cout << "Error converting the message to string" << endl;
        return false;
    }
    unsigned char* serialized_message;
    int serialized_message_len = str.length() + 1;
    serialized_message = from_string_to_unsigned_char(str);

    unsigned char* ciphertext;
    int ciphertext_len;
    unsigned char* tag;
    int tag_len = TAG_SIZE;
    //cout << "tag len: " << tag_len << endl;
    ret = gcm_encrypt(serialized_message,serialized_message_len, iv, IV_GCM, key, iv, IV_GCM, ciphertext, ciphertext_len,tag, tag_len);
    if(ret == -1){
        cout << "Error encrypting the message" << endl;
        return false;
    }
    uint32_t ciphertext_len_net = htonl(ciphertext_len);
    ret = send(fd, &ciphertext_len_net, sizeof(uint32_t), 0);
    //cout << "Ciphertext len: " << ntohl(ciphertext_len_net) << endl;
    if(ret < 0){
        cout << "Error sending the ciphertext size" << endl;
        return false;
    }

    ret = send(fd, ciphertext, ciphertext_len, 0);
    //cout << "Ciphertext: " << ciphertext << endl;
    //BIO_dump_fp(stdout, (const char*)ciphertext, ciphertext_len);
    if(ret < 0){
        cout << "Error sending the ciphertext" << endl;
        return false;
    }   
    ret = send(fd, tag, tag_len,0);
    //cout << "Tag: " << tag << endl;

    if(ret < 0){
        cout<<"Error sending the tag"<<endl;
        return false;
    }

    delete[] ciphertext;
    delete[] tag;
    delete[] serialized_message;
    delete[] iv;
    return true;
}


bool receive_auth_and_encrypted_message(int fd, network_message &message, unsigned char* key){
    int ret;
    unsigned char* iv = new unsigned char[IV_GCM];
    ret = recv(fd, iv, IV_GCM, 0);
    //cout << "IV: " << iv << endl;
    //cout << "IV len: " << strlen((char*)iv) << endl;
    if(ret == 0){
        cout << "Connection closed" << endl;
        delete[] iv;
        return false;

    }
    if(ret < 0){
        cout << "Error receiving the IV" << endl;
        delete[] iv;
        return false;
    }
    uint32_t ciphertext_len_net;
    ret = recv(fd, &ciphertext_len_net, sizeof(uint32_t), 0);
    if(ret == 0){
        cout << "Connection closed" << endl;
        return false;
    }
    //cout << "Ciphertext len: " << ntohl(ciphertext_len_net) << endl;
    if(ret < 0){
        cout << "Error receiving the ciphertext size" << endl;
        return false;
    }
    int ciphertext_len = ntohl(ciphertext_len_net);
    unsigned char* ciphertext = new unsigned char[ciphertext_len];
    ret = recv(fd, ciphertext, ciphertext_len, 0);
    if(ret == 0){
        cout << "Connection closed" << endl;
        return false;
    }
    //cout << "Ciphertext: " << ciphertext << endl;
    //BIO_dump_fp(stdout, (const char*)ciphertext, ciphertext_len);
    if(ret < 0){
        cout << "Error receiving the ciphertext" << endl;
        delete[] ciphertext;
        return false;
    }
    unsigned char* tag = new unsigned char[TAG_SIZE];
    ret = recv(fd, tag, TAG_SIZE, 0);
    if(ret == 0){
        cout << "Connection closed" << endl;
        return false;
    }
    //cout << "Tag: " << tag << endl;
    if(ret < 0){
        cout << "Error receiving the tag" << endl;
        delete[] ciphertext;
        delete[] tag;
        return false;
    }
    unsigned char* plaintext;
    int plaintext_len;
    ret = gcm_decrypt(ciphertext, ciphertext_len, iv, IV_GCM, tag, TAG_SIZE, key, iv, IV_GCM, plaintext, plaintext_len);
    if(ret == -1){
        cout << "Error decrypting the message" << endl;
        delete[] ciphertext;
        delete[] tag;
        delete[] plaintext;
        return false;
    }
    //cout << "Plaintext: " <<(char*)plaintext << endl;
    //cout << "Plaintext_len: " << plaintext_len << endl;
   
    if(!from_string_to_network_message((char*)plaintext, message)){
        cout << "Error deserializing the message" << endl;
        delete[] ciphertext;
        delete[] tag;
        delete[] plaintext;
        return false;
    }
    delete[] ciphertext;
    delete[] tag;
    delete[] plaintext;
    return true;
}

bool from_network_message_to_string(network_message message, string &str){
    str = "Nonce: " + to_string(message.nonce) + "\n";
    str += "Request: " + to_string(message.request) + "\n";
    str += "Content length: " + to_string(message.content_length) + "\n";
    str += "Content: " + message.content + "\n";
    return true;
}

bool from_string_to_network_message(string str, network_message &message){
    regex re("Nonce: (\\d+)\nRequest: (\\d+)\nContent length: (\\d+)\nContent: (.+)\n");
    smatch match;
    if(regex_search(str, match, re)){
        message.nonce = stoi(match[1]);
        message.request = stoi(match[2]);
        message.content_length = stoi(match[3]);
        message.content = match[4].str();
        return true;
    }
    return false;
}
