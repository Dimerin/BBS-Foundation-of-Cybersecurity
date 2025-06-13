//Command IDs
#define REGISTER_COMMAND 1
#define LOGIN_COMMAND 2
#define LIST_COMMAND 3
#define GET_COMMAND 4
#define ADD_COMMAND 5
#define LOGOUT_COMMAND 6
#define LIST_COMMAND_OK 13
#define LIST_COMMAND_ERROR 113
#define GET_COMMAND_OK 14
#define GET_COMMAND_ERROR 114   
#define ADD_COMMAND_OK 15
#define ADD_COMMAND_ERROR 115
#define LOGOUT_COMMAND_OK 16
#define LOGOUT_COMMAND_ERROR 116

//Generic Client Constants
#define EMAIL_LEN 8
#define PASSWORD_LEN 16
#define USERNAME_LEN 4
#define PORT 4242
#define LOCALHOST "127.0.0.1"

//Generic Server Constants
#define MAX_CLIENTS 50
#define BUF_LEN 4096
#define POST_PATH "DataServer/posts.txt"
#define KEY_PATH "DataServer/key.txt"
#define RESPONSE_OK 200
#define RESPONSE_ERROR_NOT_EXISTS 404
#define RESPONSE_ERROR_PSW 401
#define MAX_POST_ID 65535
#define SESSION_EXPIRED 255
#define SESSION_ERROR 100
#define GENERIC_ERROR 99

//Crypto Constants
#define FRAGMENT_SIZE 16
#define AES128_BLOCK_SIZE 16
#define AES128_KEY_SIZE 128
#define BLOCK_SIZE 16
#define RSA_KEY_SIZE 256
#define TAG_SIZE 16
#define OTP_SIZE 4
#define HASH_LEN 32
#define IV_GCM 12
