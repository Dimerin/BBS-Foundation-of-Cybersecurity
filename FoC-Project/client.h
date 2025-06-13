#include <iostream>
#include <vector>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string>
#include "constants.h"
#include "crypto.h"
#include "utility.h"
#include <regex>
#include <cstdlib> // For system()

using namespace std;



struct Post {
    int id;
    string title;
    string author;
    string body;
};

class Client {
    private:
        struct sockaddr_in srv_addr,cli_addr;
        int sd, ret;
        string _command;
        bool logged;
        string _username;
        string _email;
        string _password;
        string _otp;
        uint16_t _freshness;
        bool _logged;
        char buffer[BUF_LEN];
        EVP_PKEY* _DH_client_private_key;
        unsigned char* _DH_client_public_key;
        int _DH_client_public_key_len;
        unsigned char* _DH_server_public_key;
        int _DH_server_public_key_len;
        unsigned char* _session_key;
        int _session_key_len;
        vector<Post> posts;
        

    public:
        Client();
        void handler_standard_input();
        bool handler_login();
        bool handler_register();
        bool handler_logout();
        bool handler_list();
        bool handler_get();
        bool handler_add();
        void handler_shutdown();
        void showPosts();
        vector<Post> StringToPosts(string str);
        void showPosts(vector<Post> p);
        void print_dialog();
        void clean_client();
};