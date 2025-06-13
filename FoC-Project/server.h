#include <iostream>
#include <vector>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "crypto.h"
#include "constants.h"
#include "utility.h"
#include <string.h>
#include <sstream>
#include <vector>
#include <limits>
#include <fstream>



using namespace std;

struct Post {
    int id;
    string title;
    string author;
    string body;
};

struct User {
        string email;
        string username;
        unsigned char* password;
        unsigned char* DH_pubkey;
        int DH_pubkey_len;
        unsigned char* session_key; 
        int session_key_len;
        unsigned char otp_server[OTP_SIZE];
        uint16_t freshness;
        bool logged;


    User() : email(""), username(""), password(nullptr) {}

    User(string email, string username, unsigned char* password)
        : email(email), username(username), password(password), DH_pubkey(nullptr) {}
};


class Server {
public:
    Server(int);
    void handle_new_connection(int);
    void handle_standard_input(int);
    void handle_client_message(int);
    void handle_logged_user_message(int);
    void start();
    bool loadKey();
    bool loadPrivateKey();
    bool savePosts(vector<Post>);
    bool insertPost(Post);
    bool AppendUserToFile(User);
    User FindUserFromFile(string);
    unsigned char* PostToString(Post);
    Post StringToPost(unsigned char*);
    Post NetworkStringToPost(string, int);
    Post FindPostById(int);
    int loadPosts();
    bool loadVector(char*,int);
    void showPosts();
    vector<Post> GetLastPosts(int);
    User createUser(unsigned char*,bool);
    string sendChallenge(string);
    void deleteChallenge(string);
    bool cleanClient(int);
    bool createIV();
    bool createPostKey();

private:
    int server_fd,new_socket,client;
    int client_sockets[MAX_CLIENTS];
    struct sockaddr_in address;
    fd_set master,read_fds;
    char buffer[BUF_LEN];
    int fdmax, ret, addrlen;
    string input;
    EVP_PKEY* server_prvkey_RSA;
    unsigned char* DH_server_public_key;
    EVP_PKEY* DH_server_private_key;
    int DH_server_public_key_len;
    unsigned char* serverkey;
    unsigned char* IV_POST;
    vector<Post> posts;
    vector<User> users;
    uint16_t number_of_posts;
};

