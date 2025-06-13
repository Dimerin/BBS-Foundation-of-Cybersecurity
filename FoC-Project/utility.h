#include <string>
#include <iostream>
#include <iomanip>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <time.h>
#include <sys/select.h> 
#include <unistd.h>
#include <regex>
#include "constants.h"
#include "crypto.h"


using namespace std;

struct network_message{
    uint16_t nonce;
    uint8_t request;
    uint16_t content_length;
    string content;    
};

string byte_to_hex(unsigned char* hash);

unsigned char* from_string_to_unsigned_char(string str);

bool send_RSA_message(int fd, EVP_PKEY* key, unsigned char* message, int message_len);

bool receive_RSA_message(int fd, EVP_PKEY* key, unsigned char*& message, int& message_len);

bool send_public_key_DH(int fd, unsigned char* DH_pub_key, int DH_pub_key_len,unsigned char* iv);

bool receive_public_key_DH(int fd, unsigned char*& DH_pub_key, int& DH_pub_key_len, unsigned char*& iv);

bool send_message_gcm(int fd, unsigned char* message, int message_len, unsigned char* key, unsigned char* iv);

bool receive_message_gcm(int fd, unsigned char*& message, int& message_len, unsigned char* key, unsigned char* iv);

bool send_encrypted_message(int fd, unsigned char* message, int message_len, unsigned char* key, unsigned char* iv);

bool receive_encrypted_message(int fd, unsigned char*& message, int& message_len, unsigned char* key, unsigned char* iv);

bool send_auth_and_encrypted_message(int fd, network_message message, unsigned char* key);

bool receive_auth_and_encrypted_message(int fd, network_message& message, unsigned char* key);

bool from_network_message_to_string(network_message message, string& str);

bool from_string_to_network_message(string str, network_message& message);