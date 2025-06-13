#include "server.h"



Server::Server(int port){
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    for(int i=0; i<MAX_CLIENTS; i++){
        client_sockets[i] = 0;
    }
    if(server_fd == 0){
        perror("Failed to create listener socket\n");
        exit(EXIT_FAILURE);
    }
    memset(&address, '0', sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);
    if(bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0){
        perror("Failed to bind\n");
        exit(EXIT_FAILURE);
    }
    if (listen(server_fd, MAX_CLIENTS) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }
    FD_ZERO(&read_fds);
    FD_ZERO(&master);
    FD_SET(STDIN_FILENO,&master);
    FD_SET(server_fd, &master);
    fdmax = server_fd;
    users.resize(MAX_CLIENTS);
    for(int i=0; i<MAX_CLIENTS; i++){
        users[i].logged = false;
        users[i].freshness = 0;
    }    
    loadPrivateKey();
    loadKey();
    if(loadPosts() == 0 ){
        cout << "No post to load !" << endl;
    }
    else if(loadPosts() == -1){
        cout << "Error loading posts" << endl;
    }
    else {
        cout << "Posts loaded" << endl;
    }
    number_of_posts = posts.size();
}

void Server::start(){
    while(1){
        read_fds = master;
        ret = select(fdmax+1,&read_fds, NULL, NULL, NULL);
        if(ret<0) {
            perror("Failed to select \n");
            exit(1);    
        }
        for(int i=0; i <= fdmax; i++){
            if(FD_ISSET(i,&read_fds)){
                if(i == server_fd){
                    handle_new_connection(i);
                }
                else if(i == STDIN_FILENO){
                    handle_standard_input(i);
                }
                else if(!users[i].logged){
                    handle_client_message(i);
                }
                else{
                    handle_logged_user_message(i);
                }
            }
        }
    }
}

bool Server::createIV(){
    IV_POST = new unsigned char[AES128_BLOCK_SIZE];
    if(RAND_bytes(IV_POST, AES128_BLOCK_SIZE) == 0){
        return false;
    }
    FILE *iv_file = fopen("DataServer/iv_post.pem", "wb");
    if(iv_file == NULL){
        perror("Failed to open iv file\n");
        exit(EXIT_FAILURE);
        return false;
    }
    fwrite(IV_POST, 1, AES128_BLOCK_SIZE, iv_file);
    return true;

}

bool Server::createPostKey(){
    serverkey = new unsigned char[AES128_KEY_SIZE];
    if(RAND_bytes(serverkey, AES128_KEY_SIZE) == 0){
        return false;
    }
    FILE *keyfile = fopen("DataServer/server_key_private.pem", "wb");
    if(keyfile == NULL){
        perror("Failed to open key file\n");
        exit(EXIT_FAILURE);
        return false;
    }
    fwrite(serverkey, 1, AES128_KEY_SIZE, keyfile);
    return true;
}

bool Server::cleanClient(int fd){
    if(fd < 0 || fd >= MAX_CLIENTS){
        return false;
    }
    users[fd].logged = false;
    users[fd].freshness = 0;
    users[fd].username = "";
    users[fd].email = "";
    users[fd].password = nullptr;
    users[fd].DH_pubkey = nullptr;
    users[fd].session_key = nullptr;
    users[fd].session_key_len = 0;
    users[fd].DH_pubkey_len = 0;
    users[fd].DH_pubkey = nullptr;
    users[fd].DH_pubkey_len = 0;
    return true;
}

void Server::handle_new_connection(int i) {
    cout << "New client connection"<< endl;
    addrlen = sizeof(client);
    if((new_socket = accept(server_fd, (struct sockaddr *)&client, (socklen_t*)&addrlen)) < 0){
        perror("Failed to accept\n");
        exit(EXIT_FAILURE);
    }else{
        FD_SET(new_socket, &master);
        if(new_socket > fdmax){
            fdmax = new_socket;
        }
    }
}

void Server::handle_standard_input(int i) {
    cin >> input;
    if(input == "exit"){
        users.clear();
        cout << "Encrypting posts..." << endl;
        savePosts(posts);
        delete [] IV_POST;
        delete [] serverkey;
        EVP_PKEY_free(server_prvkey_RSA);
        cout << "Exiting server..." << endl;
        for(int i = 1; i < fdmax; i++) {
            close(i); // Close each client connection
        }
        close(server_fd);
        exit(0);
    }
    
   // -------------DEBUG--------------------------
    if(input == "1"){
        cout << "Memory Vector" << endl;
        showPosts();
        
    }
    if(input == "2"){
        Post post;
        string id;
        cout << "Enter post id: ";
        cin >> post.id;
        cin.ignore(numeric_limits<streamsize>::max(), '\n'); // Ignore the newline character
        cout << post.id << endl;
        cout << "Enter post title: ";
        getline(cin, post.title);
        cout << post.title << endl;
        cout << "Enter post author: ";
        getline(cin, post.author);
        cout << post.author << endl;
        cout << "Enter post body: ";
        getline(cin, post.body);
        cout << post.body << endl;
        insertPost(post);
    }
    if(input == "3"){
        savePosts(posts);
    }
    if(input == "4"){
        cout << "Memory Vector" << endl;
        loadPosts();
    }
    
}

bool Server::loadPrivateKey(){
    server_prvkey_RSA = read_key_from_file("keys/rsa_private_key_server.pem", false);
    if(server_prvkey_RSA == NULL){
        perror("Failed to load private key\n");
        exit(EXIT_FAILURE);
        return false;
    }
    return true;
}

bool Server::AppendUserToFile(User user){
    FILE *userfile = fopen("DataServer/users.txt", "ab");
    if(userfile == NULL){
        perror("Failed to open userfile\n");
        exit(EXIT_FAILURE);
        return false;
    }
    string userstr = user.email + "-" + user.username + "-" + string((char*)user.password) + "|";
    fwrite(userstr.c_str(), 1, userstr.length(), userfile);
    fclose(userfile);
    return true;
}


User Server::FindUserFromFile(string username){
    FILE *userfile = fopen("DataServer/users.txt", "rb");
    if(userfile == NULL){
        perror("Failed to open userfile\n");
        exit(EXIT_FAILURE);
    }
    fseek(userfile, 0, SEEK_END);
    size_t filesize = ftell(userfile);
    rewind(userfile);
    unsigned char* buffer = (unsigned char*)malloc(filesize);
    if (fread(buffer, 1, filesize, userfile) != filesize) {
        perror("Failed to read userfile\n");
        exit(EXIT_FAILURE);
    }
    fclose(userfile);
    stringstream ss((char*)buffer);
    string user_line;
    while (getline(ss, user_line, '|')) {
        stringstream userStream(user_line);
        string field;
        vector<string> fields;
        while (getline(userStream, field, '-')) {
            fields.push_back(field);
        }
        if (fields.size() == 3) {
            User newUser(fields[0], fields[1], from_string_to_unsigned_char(fields[2]));
            if (newUser.username == username) {
                return newUser;
            }
        }
    }
    return User();       
}
string Server::sendChallenge(string email){
    // Create a directory named "email"
    string dirPath = "email/";
    mkdir(dirPath.c_str(), 0777); // 0777 is the permission
    // Create a file path
    string filePath = dirPath + email;

    // Generate a random OTP
    unsigned char otp[OTP_SIZE];
    if (RAND_bytes(otp, sizeof(otp)) != 1) {
        // Handle error
        return "";
    }

    // Convert the OTP to a hexadecimal string
    string otpHex;
    for (size_t i = 0; i < sizeof(otp); i++) {
        char hex[3];
        sprintf(hex, "%02x", otp[i]);
        otpHex += hex;
    }
    //Write the OTP inside the User specific object
    
    // Write the OTP to the file
    ofstream file(filePath);
    if (file.is_open()) {
        file << otpHex;
        file.close();
    } else {
        // Handle error
        return "";
    }
    return otpHex;
}

void Server::deleteChallenge(string email){
    string dirPath = "email/";
    string filePath = dirPath + email;
    remove(filePath.c_str());
}
void Server::handle_client_message(int i) {
    memset(buffer,0,BUF_LEN);
    if((ret = recv(i, buffer, BUF_LEN, 0)) == 0){
        cout << "Client disconnected\n";
        users[i].logged = false;
        close(i);
        FD_CLR(i, &master);
    }
    else{
        if(strcmp(buffer, to_string(REGISTER_COMMAND).c_str()) == 0){
            //cout << "Received register command. Buffer:"<< buffer << endl;
            unsigned char* buffer_received;
            int buffer_len,ret;
            unsigned char* success = new unsigned char;
            receive_RSA_message(i, server_prvkey_RSA, buffer_received, buffer_len);
            User newUser = createUser(buffer_received, false);
            
            //Starting the challenge
            string check_otp = sendChallenge(newUser.email);
            unsigned char* otp;
            int otp_len;
         
            receive_RSA_message(i, server_prvkey_RSA, otp, otp_len);
            if(check_otp == string((char*)otp) && FindUserFromFile(newUser.username).username == ""){
                cout << "OTP correct" << endl;
                cout << "User registered:" << newUser.username << endl;
                *success = '1';
                deleteChallenge(newUser.email);
                //send_encrypted_message(i, success, sizeof(success), newUser.session_key, (unsigned char*)"012345678912345");
                //users.push_back(newUser);
                ret = send(i, success, sizeof(success), 0);
                if(ret == -1){
                    perror("Failed to send response\n");
                }
                AppendUserToFile(newUser);
            }
            else if(check_otp != string((char*)otp)){
                cout << "OTP incorrect, unable to identify the user" << endl;
                *success = '0';
                deleteChallenge(newUser.email);
                //send_encrypted_message(i, success,sizeof(success), newUser.session_key, (unsigned char*)"012345678912345");
                ret = send(i, success, sizeof(success), 0);
                if(ret == -1){
                    perror("Failed to send response\n");
                }
            }
            else if(FindUserFromFile(newUser.username).username != ""){
                cout << "User already registered" << endl;
                *success = '2';
                deleteChallenge(newUser.email);
                //send_encrypted_message(i, success,sizeof(success), newUser.session_key, (unsigned char*)"012345678912345");
                ret = send(i, success, sizeof(success), 0);
                if(ret == -1){
                    perror("Failed to send response\n");
                }
                return;
            }
            else {
                cout << "Error registering the user" << endl;
                *success = '9';
                deleteChallenge(newUser.email);
                //send_encrypted_message(i, success,sizeof(success), newUser.session_key, (unsigned char*)"012345678912345");
                ret = send(i, success, sizeof(success), 0);
                if(ret == -1){
                    perror("Failed to send response\n");
                }
            }
            delete[] success;
            delete [] otp;
        }
        else if(strcmp(buffer, to_string(LOGIN_COMMAND).c_str()) == 0){
            unsigned char* buffer_received;
            int buffer_len;
            receive_RSA_message(i, server_prvkey_RSA, buffer_received, buffer_len);
            //Checking if the user is already registered or if the password is correct:
            User newUser = createUser(buffer_received, true);
            delete [] buffer_received;
            int ret,response;
            bool user_exists = false;
            User logged_user = FindUserFromFile(newUser.username);
            if(logged_user.username == ""){
                response = RESPONSE_ERROR_NOT_EXISTS;
                user_exists = false;
                ret = send(i,&response,sizeof(response),0);
                if(ret == -1){
                    perror("Failed to send response\n");
                }
                return;
            }
            else {
                user_exists = true;
            }
            if(user_exists && memcmp(logged_user.password, newUser.password, HASH_LEN) == 0){
                response = RESPONSE_OK;
                ret = send(i, &response, sizeof(response), 0);
                if(ret == -1){
                    perror("Failed to send response\n");
                }
                users[i] = logged_user;
                DH_server_private_key  = EVP_PKEY_new();
                //Extracting the public key
                DH_private_key_generation(DH_server_private_key);
                if(DH_server_private_key == NULL){
                    perror("Failed to generate the DH private key\n");
                    return;
                }
                dh_pub_key_serialization(DH_server_private_key, DH_server_public_key, DH_server_public_key_len);
                if(DH_server_public_key == NULL){
                    perror("Failed to retrieve the DH public key\n");
                    return;
                }
                //Creating a session key
                unsigned char* DH_pub_key_encrypted;
                unsigned char* DH_pub_key;
                int DH_pub_key_len;
                unsigned char* DH_iv;
                receive_public_key_DH(i, DH_pub_key_encrypted, DH_pub_key_len,DH_iv);
                //cout << "Public Key Server start: " << byte_to_hex(DH_server_public_key) << endl;
                DH_pub_key = new unsigned char[DH_pub_key_len];
                aes_decrypt(DH_pub_key_encrypted, DH_pub_key_len, users[i].password, DH_iv, DH_pub_key);
                //cout << "Public key received:" << byte_to_hex(DH_pub_key) << endl;
                users[i].DH_pubkey = new unsigned char[DH_pub_key_len];
                memcpy(users[i].DH_pubkey, DH_pub_key, DH_pub_key_len);
                users[i].DH_pubkey_len = DH_pub_key_len;
                delete[] DH_pub_key_encrypted;
                delete[] DH_pub_key;
                delete[] DH_iv;
                //unsigned char* DH_server_public_key_encrypted;
                //int DH_server_public_key_encrypted_len;
                //DHE_key_exchange(DH_server_private_key, newUser.password, DH_server_public_key_encrypted, DH_server_public_key_encrypted_len);
                unsigned char* DH_iv_answer = new unsigned char[AES128_BLOCK_SIZE];
                if(RAND_bytes(DH_iv_answer, AES128_BLOCK_SIZE) == 0){
                    cout << "Error generating the IV" << endl;
                    return;
                }
                unsigned char* DH_server_public_key_encrypted = new unsigned char[DH_server_public_key_len + BLOCK_SIZE];
                int DH_server_public_key_encrypted_len = aes_encrypt(DH_server_public_key, DH_server_public_key_len, users[i].password, DH_iv_answer, DH_server_public_key_encrypted);
                //cout << "PUBLIC KEY SERVER :" << byte_to_hex(DH_server_public_key) << endl;
                send_public_key_DH(i, DH_server_public_key_encrypted, DH_server_public_key_encrypted_len, DH_iv);
                //cout << "Public key sent" << endl;
                delete [] DH_server_public_key_encrypted;
                delete [] DH_iv_answer;
                //Creating a session key
                unsigned char* session_key;
                unsigned int session_key_len;
                EVP_PKEY* client_pubkey;
                //EVP_PKEY* client_pubkey = DH_create_pub_key_from_unsigned(newUser.DH_pubkey, newUser.DH_pubkey_len);
                dh_pub_key_deserialization(client_pubkey, users[i].DH_pubkey, users[i].DH_pubkey_len);
                //cout << "Client public key: " << client_pubkey << endl;
                DHE_create_session_key(DH_server_private_key, client_pubkey, DH_pub_key_len, session_key, session_key_len);
                if(session_key == NULL){
                    cout << "Error creating the session key" << endl;
                }                
                users[i].session_key = new unsigned char[session_key_len];
                memcpy(users[i].session_key, session_key, session_key_len);
                //cout << "Session key created for user:" << users[i].username << endl;
                delete [] session_key;
                EVP_PKEY_free(client_pubkey);
                //cout << "Session key:" << byte_to_hex(users[i].session_key) << endl;
                users[i].logged = true;
                EVP_PKEY_free(DH_server_private_key);
            }
            else{
                response = RESPONSE_ERROR_PSW;
                ret = send(i, &response, sizeof(response), 0);
                if(ret == -1){
                    perror("Failed to send response\n");
                }
            }
        } 
        else{
           cout << "Inside the else of non registered user" << endl;
        }          
    } 
}
void Server::handle_logged_user_message(int i){
        network_message message;
        if(!receive_auth_and_encrypted_message(i, message, users[i].session_key)){
            cout << "Client disconnected\n";
            cleanClient(i);
            close(i);
            FD_CLR(i, &master);
        }else{
           switch(message.request){
            case LIST_COMMAND:
                {
                    //cout << "Received list command" << endl;
                    int n = stoi(message.content);
                    vector<Post> lastPosts = GetLastPosts(n);
                    network_message response;
                    bool session_expired;
                    if(users[i].freshness+1 == SESSION_EXPIRED){
                        session_expired = true;
                    }
                    else{
                        session_expired = false;
                    }
                    if(!lastPosts.size() == 0 && message.nonce == users[i].freshness && !session_expired){
                        response.nonce = users[i].freshness;
                        response.request = LIST_COMMAND_OK;
                        string str;
                        for(Post post : lastPosts){
                            unsigned char* poststr = PostToString(post);
                            str += string((char*)poststr);
                        }
                        response.content = str;
                        response.content_length = str.length();
                        send_auth_and_encrypted_message(i, response, users[i].session_key);       
                    }
                    else if(lastPosts.size() == 0 && message.nonce == users[i].freshness && !session_expired){
                        network_message response;
                        response.nonce = users[i].freshness;
                        response.request = LIST_COMMAND_ERROR;
                        response.content_length = 1;
                        response.content = "0";
                        send_auth_and_encrypted_message(i, response, users[i].session_key);
                    }
                    else if(session_expired){
                        network_message response;
                        response.nonce = users[i].freshness;
                        response.request = SESSION_EXPIRED;
                        response.content_length = 1;
                        response.content = "0";
                        send_auth_and_encrypted_message(i, response, users[i].session_key);
                        cleanClient(i);
                    }
                    else if(message.nonce != users[i].freshness && !session_expired){
                        network_message response;
                        response.nonce = users[i].freshness;
                        response.request = SESSION_ERROR;
                        response.content_length = 1;
                        response.content = "0";
                        send_auth_and_encrypted_message(i, response, users[i].session_key);
                        cleanClient(i);
                    }
                    else{ 
                        network_message response;
                        response.nonce = users[i].freshness;
                        response.request = GENERIC_ERROR;
                        response.content_length = 1;
                        response.content = "0";
                        send_auth_and_encrypted_message(i, response, users[i].session_key);
                    }                
                    users[i].freshness++;
                } 
                break;
            case GET_COMMAND:
                {
                //cout << "Received get command" << endl;
                int id = stoi(message.content);
                Post post;
                post = FindPostById(id);
                network_message response;

                bool session_expired;
                if(users[i].freshness+1 == SESSION_EXPIRED){
                    session_expired = true;
                }
                else{
                    session_expired = false;
                }

                if(post.id == 0 && message.nonce == users[i].freshness && !session_expired){
                    cout << "Post not found" << endl;
                    response.request = GET_COMMAND_ERROR;
                    response.content = "0";
                    response.content_length = 1;
                    response.nonce = users[i].freshness;
                    send_auth_and_encrypted_message(i, response, users[i].session_key);
                }
                else if (post.id != 0 && message.nonce == users[i].freshness && !session_expired){
                    cout << "Post found" << endl;
                    response.nonce = users[i].freshness;
                    response.request = GET_COMMAND_OK;
                    unsigned char* poststr = PostToString(post);
                    response.content = string((char*)poststr);
                    response.content_length = strlen((char*)poststr);
                    send_auth_and_encrypted_message(i, response, users[i].session_key);
                    delete[] poststr;
                }
                else if(session_expired){
                    network_message response;
                    response.nonce = users[i].freshness;
                    response.request = SESSION_EXPIRED;
                    response.content_length = 1;
                    response.content = "0";
                    send_auth_and_encrypted_message(i, response, users[i].session_key);
                    cleanClient(i);
                }
                else if(message.nonce != users[i].freshness && !session_expired){
                    network_message response;
                    response.nonce = users[i].freshness;
                    response.request = SESSION_ERROR;
                    response.content_length = 1;
                    response.content = "0";
                    send_auth_and_encrypted_message(i, response, users[i].session_key);
                    cleanClient(i);
                }
                else{ 
                    network_message response;
                    response.nonce = users[i].freshness;
                    response.request = GENERIC_ERROR;
                    response.content_length = 1;
                    response.content = "0";
                    send_auth_and_encrypted_message(i, response, users[i].session_key);
                }
                users[i].freshness++;
                }
                break;
            case ADD_COMMAND:
            {
                //cout << "Received add command" << endl;
                Post newPost = NetworkStringToPost(message.content, number_of_posts+1);
                network_message response;
                bool session_expired;
                if(users[i].freshness+1 == SESSION_EXPIRED){
                    session_expired = true;
                }
                else{
                    session_expired = false;
                }
                if(newPost.id == 0 && message.nonce == users[i].freshness && !session_expired){
                    cout << "Error creating post" << endl;
                    response.nonce = users[i].freshness;
                    response.request = ADD_COMMAND_ERROR;
                    response.content_length = 1;
                    response.content = "0";
                    send_auth_and_encrypted_message(i, response, users[i].session_key);
                }
                else if(newPost.id != 0 && message.nonce == users[i].freshness && !session_expired) {
                    cout << "Post created" << endl;
                    response.nonce = users[i].freshness;
                    response.request = ADD_COMMAND_OK;
                    response.content_length = 1;
                    response.content = "1";
                    send_auth_and_encrypted_message(i, response, users[i].session_key);
                    number_of_posts++;
                    insertPost(newPost);
                    
                }
                else if(session_expired){
                    network_message response;
                    response.nonce = users[i].freshness;
                    response.request = SESSION_EXPIRED;
                    response.content_length = 1;
                    response.content = "0";
                    send_auth_and_encrypted_message(i, response, users[i].session_key);
                    cleanClient(i);
                }
                else if(message.nonce != users[i].freshness && !session_expired){
                    network_message response;
                    response.nonce = users[i].freshness;
                    response.request = SESSION_ERROR;
                    response.content_length = 1;
                    response.content = "0";
                    send_auth_and_encrypted_message(i, response, users[i].session_key);
                    cleanClient(i);
                }
                else{ 
                    network_message response;
                    response.nonce = users[i].freshness;
                    response.request = GENERIC_ERROR;
                    response.content_length = 1;
                    response.content = "0";
                    send_auth_and_encrypted_message(i, response, users[i].session_key);
                }
                users[i].freshness++;
            }
                break;

            case LOGOUT_COMMAND:
            {
                //cout << "Received logout command" << endl;
                
                bool session_expired;
                if(users[i].freshness+1 == SESSION_EXPIRED){
                    session_expired = true;
                }
                else{
                    session_expired = false;
                }
                if(message.nonce == users[i].freshness && !session_expired){
                    network_message response;
                    response.request = LOGOUT_COMMAND_OK;
                    response.content_length = 1;
                    response.content = "1";
                    response.nonce = users[i].freshness;
                    send_auth_and_encrypted_message(i, response, users[i].session_key);
                    cleanClient(i);
                }
                else if(session_expired){
                    network_message response;
                    response.nonce = users[i].freshness;
                    response.request = SESSION_EXPIRED;
                    response.content_length = 1;
                    response.content = "2";
                    send_auth_and_encrypted_message(i, response, users[i].session_key);
                    cleanClient(i);
                }
                else if(message.nonce != users[i].freshness && !session_expired){
                    network_message response;
                    response.nonce = users[i].freshness;
                    response.request = SESSION_ERROR;
                    response.content_length = 1;
                    response.content = "3";
                    send_auth_and_encrypted_message(i, response, users[i].session_key);
                    cleanClient(i);
                }
                else{ 
                    network_message response;
                    response.nonce = users[i].freshness;
                    response.request = LOGOUT_COMMAND_ERROR;
                    response.content_length = 1;
                    response.content = "0";
                    send_auth_and_encrypted_message(i, response, users[i].session_key);
                    cleanClient(i);
                }    
            }
            break;
            default:
                cout << "Invalid command" << endl;
                break;
        }
    }
}

User Server::createUser(unsigned char* buffer, bool isLogin){
    if(buffer == NULL){
        cout << "Buffer empty, returning empty user" << endl;
    }
    if(!isLogin){
        string message = string((char*)buffer);
        stringstream ss(message);
        string email, username,password;
        getline(ss, email, ' ');
        getline(ss, username, ' ');
        getline(ss, password, ' ');
        User newUser(email, username, from_string_to_unsigned_char(password));
        return newUser;
    }
    else {
        string message = string((char*)buffer);
        stringstream ss(message);
        string username, password;
        getline(ss, username, ' ');
        getline(ss, password, ' ');
        User newUser("", username, from_string_to_unsigned_char(password));
        return newUser;
    }
}


bool Server::loadKey(){
    FILE *keyfile = fopen("DataServer/server_key_private.pem", "rb");
    if(keyfile == NULL){
        perror("Failed to open keyfile\n");
        exit(EXIT_FAILURE);
    }
    fseek(keyfile, 0, SEEK_END);
    long keysize = ftell(keyfile);
    fseek(keyfile, 0, SEEK_SET);
    serverkey = (unsigned char*)malloc(keysize);
    if(serverkey == NULL){
        perror("Failed to allocate memory for key\n");
        return false;
    }
    IV_POST = (unsigned char*)malloc(BLOCK_SIZE);
    FILE *ivfile = fopen("DataServer/iv_post.pem", "rb");
    if(ivfile == NULL){
        perror("Failed to open ivfile\n");
        return false;
    }
    if(IV_POST == NULL){
        perror("Failed to allocate memory for IV\n");
        return false;
    }
    fread(serverkey, 1, keysize, keyfile);
    fread(IV_POST, 1, AES128_BLOCK_SIZE, ivfile);
    //fread(iv, 1, keysize, keyfile);
    fclose(keyfile);
    fclose(ivfile);
    return true;
}

unsigned char* Server::PostToString(Post post){
    string poststr = to_string(post.id) + "-" + post.title + "-" + post.author + "-" + post.body + "|";
    
    unsigned char* postchar = (unsigned char*)malloc(poststr.length()+1);
   
    if(postchar == NULL){
        perror("Failed to allocate memory for post\n");
        return nullptr;
    }
    strcpy((char*)postchar, poststr.c_str());
    return postchar;
}

Post Server::StringToPost(unsigned char* poststr){
    string str((char*)poststr);
    stringstream ss(str);
    string post;
    getline(ss, post, '-');
    Post newPost;
    newPost.id = stoi(post);
    getline(ss, post, '-');
    newPost.title = post;
    getline(ss, post, '-');
    newPost.author = post;
    getline(ss, post, '-');
    newPost.body = post;
    return newPost;
}

Post Server::NetworkStringToPost(string str, int id){
    stringstream ss(str);
    string post;
    Post newPost;
    newPost.id = id;    
    getline(ss, post, '-');
    newPost.title = post;
    getline(ss, post, '-');
    newPost.author = post;
    getline(ss, post, '-');
    newPost.body = post;
    return newPost;
}

bool Server::savePosts(vector<Post> posts){
     if(posts.size() == 0){
        cout << "No posts to save" << endl;
        return true;
    }
    FILE *postfile = fopen(POST_PATH, "wb");
    if(postfile == NULL){
        perror("Failed to open postfile\n");
        return false;
    }
    string allPosts;
    if(!createIV()){
        cout << "Error creating IV" << endl;
        return false;
    }
    if(!createPostKey()){
        cout << "Error creating post key" << endl;
        return false;
    }
    for (Post post : posts) {
        unsigned char* poststr = PostToString(post);
        allPosts += string((char*)poststr); 
    }
    unsigned char* poststr = (unsigned char*)allPosts.c_str();
  
    unsigned char* encrypter_str = (unsigned char*)malloc(strlen((char*)poststr) + BLOCK_SIZE);
    int ciphertext_len = aes_encrypt(poststr, strlen((char*)poststr), serverkey, IV_POST, encrypter_str);
   
    if(ciphertext_len == -1){
        perror("Failed to encrypt post\n");
        return false;
    }
    fwrite(encrypter_str, 1, ciphertext_len, postfile); // Write the encrypted posts
    free(encrypter_str);
    fclose(postfile);
    return true;
}


int Server::loadPosts(){
    FILE *postfile = fopen(POST_PATH, "rb");
    if(postfile == NULL){
        perror("Failed to open postfile\n");
        return -1;
    }

    // Get the size of the file
    fseek(postfile, 0, SEEK_END);
    size_t filesize = ftell(postfile);
      if(filesize <= 0 || postfile == NULL){
        return 0;
    }

    rewind(postfile);
  
    // Allocate memory for the buffer
    unsigned char* buffer = (unsigned char*)malloc(filesize+1);
    if (fread(buffer, 1, filesize, postfile) != filesize) {
        cout << "Failed to read the post file" << endl;
        return 0;
    }
    fclose(postfile);

    // Allocate memory for the decrypted string
    unsigned char* decrypted_str = (unsigned char*)malloc(filesize);

    int plaintext_len = aes_decrypt(buffer, filesize, serverkey, IV_POST, decrypted_str);
   
    if(plaintext_len == -1){
        perror("Failed to decrypt post\n");
        return -1;
    }
    // Null-terminate the decrypted string
    decrypted_str[plaintext_len] = '\0';

    // Print the decrypted string
    loadVector((char*)decrypted_str, plaintext_len);
    // Free the allocated memory
    free(buffer);
    free(decrypted_str);
    return 1;
}

Post Server::FindPostById(int id){
    for(Post post : posts){
        if(post.id == id){
            return post;
        }
    }
    return Post();
}

bool Server::loadVector(char* poststr, int len){
    if(len == 0){
        cout << "No posts to load" << endl;
        return false;
    }
    if(poststr == NULL){
        cout << "Error loading posts" << endl;
        return false;
    }

    string str(poststr, len);
    stringstream ss(str);
    string post;
    if(posts.size() != 0){
            posts.clear();
    }

    while (getline(ss, post, '|')) {
        stringstream postStream(post);
        string field;
        vector<string> fields;
        
        while (getline(postStream, field, '-')) {
            fields.push_back(field);
        }
        if (fields.size() == 4) {
            Post newPost;
            newPost.id = stoi(fields[0]);
            newPost.title = fields[1];
            newPost.author = fields[2];
            newPost.body = fields[3];
            posts.push_back(newPost);
        }
        else {
            cout << "Invalid post format" << endl;
            return false;
        }
    }
    return true;
}
bool Server::insertPost(Post post){
    posts.push_back(post);
        return true;
    return false;
}

void Server::showPosts(){
    for(Post post : posts){
        cout << "----------------------\n" << endl;
        cout << "Post ID: " << post.id << endl;
        cout << "Post Title: " << post.title << endl;
        cout << "Post Author: " << post.author << endl;
        cout << "Post Body: " << post.body << endl;
    }
}

vector<Post> Server::GetLastPosts(int n){
    vector<Post> lastPosts;
    for(int i = posts.size()-1; i >= 0 && n > 0; i--, n--){
        lastPosts.push_back(posts[i]);
    }
    return lastPosts;
}


int main () {
    Server server(4242);

    
    server.start();
    
    return 0;
}