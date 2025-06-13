#include "client.h"


Client::Client(){
    _freshness = 0;
    _logged = false;
    sd = socket(AF_INET,SOCK_STREAM,0);
    memset(&cli_addr,0,sizeof(srv_addr));
    cli_addr.sin_family = AF_INET;
    cli_addr.sin_port = PORT;
    inet_pton(AF_INET, LOCALHOST, &cli_addr.sin_addr);
    ret = bind(sd, (struct sockaddr*)&cli_addr, sizeof(cli_addr));

    memset(&srv_addr,0,sizeof(srv_addr));
    srv_addr.sin_family = AF_INET;
    srv_addr.sin_port = htons(PORT);
    inet_pton(AF_INET, LOCALHOST, &srv_addr.sin_addr);

    ret = connect(sd,(struct sockaddr*)&srv_addr, sizeof(srv_addr));
    if(ret <0){
        perror("Unable to connect with the server \n");
        exit(1);
    }
 
}

void Client::clean_client(){
    _session_key = nullptr;
    _DH_client_private_key = nullptr;
    _DH_client_public_key = nullptr;
    _DH_server_public_key = nullptr;
    _session_key_len = 0;
    _freshness = 0;
    _logged = false;
    _username = "";
    _email = "";
    _password = "";
    _otp = "";
}

void Client::handler_standard_input(){
    //print_dialog();
    while(1){
        cin >> _command;
        if(_command == "login"){
            if(!handler_login())
                continue;
            break;
            
        }
        else if(_command == "register"){
            if(!handler_register())
                continue;
            break;
           
        }
        else if(_command == "list"){
            if(!handler_list())
                continue;
            break;
            
        }
        else if(_command == "get"){
            if(!handler_get())
                continue;
            break;
            
        }
        else if(_command == "add"){
            if(!handler_add())
                continue;
            break;
        }
        else if(_command == "commandlist"){
            print_dialog();
        break;
        }
        else if(_command == "logout"){
            if(!handler_logout())
                continue;   
            break;
        }
        else if(_command == "exit"){
            handler_shutdown();
            break;
        }
        else{
            cout << "Invalid command" << endl;
            print_dialog();
        }
    }
}
void Client::print_dialog(){
    cout << "Welcome to the Bulletin Board. Enter a command:"<< endl;
    cout << "- register" << endl;
    cout << "- login" << endl;
    cout << "- logout" << endl; 
    cout << "- list <number of posts>" << endl; 
    cout << "- get <post id>" << endl;
    cout << "- add <title> <author> <body>" << endl;
    cout << "- commandlist" << endl;
    cout << "- exit" << endl;
}

void Client::showPosts(vector<Post> p){
    for(size_t i = 0; i < p.size(); i++){
        cout << "----------------------\n" << endl;
        cout << "ID: " << p[i].id << endl;
        cout << "Title: " << p[i].title << endl;
        cout << "Author: " << p[i].author << endl;
        cout << "Body: " << p[i].body << endl;
    }
    cout << "----------------------\n" << endl;
}

vector<Post> Client::StringToPosts(string postsStr){
    vector<Post> posts;
    stringstream ss(postsStr);
    string postStr;

    while (getline(ss, postStr, '|')) {
        stringstream postStream(postStr);
        string field;
        Post newPost;

        getline(postStream, field, '-');
        newPost.id = stoi(field);

        getline(postStream, field, '-');
        newPost.title = field;

        getline(postStream, field, '-');
        newPost.author = field;

        getline(postStream, field, '-');
        newPost.body = field;

        posts.push_back(newPost);
    }

    return posts;
}

void Client::handler_shutdown(){
    if(_logged){
        cout << "Logging out..." << endl;
        handler_logout();
    }
    cout << "Closing client..."<< endl;
    clean_client();
    close(sd);
    exit(0);
}

bool Client::handler_register(){
    if(_logged){
        cout << "You are already logged in" << endl;
        return false;
    }
    memset(buffer,0,BUF_LEN);
    strcpy(buffer, to_string(REGISTER_COMMAND).c_str());
    send(sd, &buffer, BUF_LEN, 0);
    string email;
    regex email_regex("(\\w+)(\\.|_)?(\\w*)@(\\w+)(\\.(\\w+))+");
    do {
        cout << "Please, insert your email: ";
        cin >> email;
        if(!regex_match(email, email_regex) || email.length() < EMAIL_LEN ) {
            cout << "The email is not valid or too short" << endl;
        }
    } while(email.length() < EMAIL_LEN || !regex_match(email, email_regex));

    _email = email;
    string username;
    do {
        cout << "Please, insert your username: ";
        cin >> username;
        if(username.length() < USERNAME_LEN) {
            cout << "The username is too short" << endl;
        }
    } while(username.length() < USERNAME_LEN);
    _username = username;

    string password;
    do{
        cout << "Please, insert your password: ";
        cin >> password;
        if(password.length() < PASSWORD_LEN) {
            cout << "The password is too short, it must be at least 16 characters." << endl;
        }
    }while(password.length() < PASSWORD_LEN);
    unsigned char* hash;
    unsigned int hash_len;
    //Hashing the password
    compute_hash_sha256((unsigned char *)password.c_str(), password.length(), hash, hash_len);
    _password = byte_to_hex(hash);
    free(hash);  //Freeing the temporal buffer
    //Loading the server public key
    EVP_PKEY* RSA_server_key = read_key_from_file("keys/rsa_public_key_server.pem", true);
    if(RSA_server_key == NULL){
        cout << "Error loading the server public key" << endl;
        return false;
    }
    //Serializing the message
    string message =  _email + " " + _username + " " + _password;
    unsigned char* envelope = from_string_to_unsigned_char(message);
    //Sending the message through RSA protocol
    send_RSA_message(sd, RSA_server_key, envelope, message.length()+1);
    delete envelope; //Freeing the serialized message
    
    //Challenge Handling:
    cout << "An email has been sent to your email address. Please, insert the OTP code: " << endl;
    do {
    cin >> _otp;
    if (_otp.length() != 8) {
        cout << "Error: OTP should be exactly 8 characters long. Please try again." << endl;
    }
    } while (_otp.length() != 8);
    unsigned char* buffer_otp = new unsigned char[_otp.length()+1];
    buffer_otp = from_string_to_unsigned_char(_otp);
    send_RSA_message(sd, RSA_server_key, buffer_otp, _otp.length()+1);
    int success_len = 1;
    unsigned char* success = new unsigned char[success_len];
    
    ret = recv(sd, success, sizeof(success), 0);
    if(ret < 0){
        cout << "Error receiving the message" << endl;
        return false;
    }
    if(success[0] == '1'){
        cout << "Registration successful" << endl;
    }
    else if(success[0] == '0'){
        cout << "Registration failed" << endl;
    }
    else if(success[0] == '2'){
        cout << "The User is already registered" << endl;
    }
    else{
        cout << "Error in the server response" << endl;
    }
    delete [] success;
    delete [] buffer_otp;
   
    handler_standard_input();
    return true;
}
bool Client::handler_login(){
    if(_logged){
        cout << "You are already logged in" << endl;
        return false;
    }
    memset(buffer,0,BUF_LEN);
    strcpy(buffer, to_string(LOGIN_COMMAND).c_str());
    send(sd, &buffer, BUF_LEN, 0);
     string username;
    do {
        cout << "Please, insert your username: ";
        cin >> username;
        if(username.length() < USERNAME_LEN) {
            cout << "The username is too short" << endl;
        }
    } while(username.length() < USERNAME_LEN);
    _username = username;

    string password;
    do{
        cout << "Please, insert your password: ";
        cin >> password;
        if(password.length() < PASSWORD_LEN) {
            cout << "The password is too short, it must be at least 16 characters." << endl;
        }
    }while(password.length() < PASSWORD_LEN);
    unsigned char* hash;
    unsigned int hash_len;
    //Hashing the password
    compute_hash_sha256((unsigned char *)password.c_str(), password.length(), hash, hash_len);
    _password = byte_to_hex(hash);
    free(hash);  //Freeing the temporal buffer
    //Loading the server public key
    EVP_PKEY* RSA_server_key = read_key_from_file("keys/rsa_public_key_server.pem", true);
    if(RSA_server_key == NULL){
        cout << "Error loading the server public key" << endl;
        return false;
    }
    string message =  _username + " " + _password;
    unsigned char* envelope = from_string_to_unsigned_char(message);
    //Sending the message through RSA protocol
    send_RSA_message(sd, RSA_server_key, envelope, message.length()+1);
    delete envelope; 
    int response;
    ret = recv(sd, &response, sizeof(response), 0);
    switch(response){
        case RESPONSE_OK:
        {
            cout << "Login successful" << endl;
             _DH_client_private_key = EVP_PKEY_new();
            if(_DH_client_private_key == NULL){
                cout << "Error generating the DH private key" << endl;
                return false;
            }
            unsigned char* DH_pubkey_encrypted;
            int DH_pubkey_encrypted_len;
            //Extracting the public key
            DH_private_key_generation(_DH_client_private_key); 
            //cout << "DH private key generated:" << _DH_client_private_key << endl;
            //_DH_client_public_key = DH_retrieve_pub_key(_DH_client_private_key, _DH_client_public_key_len);
            // dh_pub_key_serialization(_DH_client_private_key, _DH_client_public_key, _DH_client_public_key_len);
            //Encrypting the public key using the long term secret [the password]
            unsigned char* DH_iv;
            DHE_key_exchange(_DH_client_private_key, from_string_to_unsigned_char(_password),DH_pubkey_encrypted, DH_pubkey_encrypted_len, DH_iv);
            //Sending the public key to the server
            send_public_key_DH(sd, DH_pubkey_encrypted, DH_pubkey_encrypted_len, DH_iv);
            delete [] DH_pubkey_encrypted;
            //Receiving the server public key
            unsigned char* DH_server_public_key_encrypted;
            int DH_server_public_key_encrypted_len;
            DH_iv = nullptr;
            receive_public_key_DH(sd, DH_server_public_key_encrypted, DH_server_public_key_encrypted_len, DH_iv);
            unsigned char* _DH_server_public_key = new unsigned char[DH_server_public_key_encrypted_len];
            _DH_server_public_key_len = aes_decrypt(DH_server_public_key_encrypted, DH_server_public_key_encrypted_len, from_string_to_unsigned_char(_password), DH_iv,_DH_server_public_key);
            if(_DH_server_public_key_len == -1){
                cout << "Error decrypting the server public key" << endl;
                return false;
            }
            //cout << "Server public key received" << endl;
            delete [] DH_server_public_key_encrypted;
            delete [] DH_iv;

            //creating a session key
            unsigned char* session_key;
            unsigned int session_key_len;
            EVP_PKEY* s_pubkey;
            dh_pub_key_deserialization(s_pubkey, _DH_server_public_key, _DH_server_public_key_len);
            DHE_create_session_key(_DH_client_private_key, s_pubkey, _DH_server_public_key_len, session_key, session_key_len);
            if(session_key == NULL){
                cout << "Error creating the session key" << endl;
                return false;
            }
            _session_key = session_key;
            _session_key_len = session_key_len;
            cout << "Now you can access securely at the Bulletin Board services" << endl;
            _logged = true;
            delete [] _DH_server_public_key;
            EVP_PKEY_free(s_pubkey);
            EVP_PKEY_free(_DH_client_private_key);
           
        }
        break;
        case RESPONSE_ERROR_NOT_EXISTS:
            cout << "The user is not registered" << endl;
            break;
        case RESPONSE_ERROR_PSW:
            cout << "The password is incorrect" << endl;
            break;
        default:
            cout << "Error in the server response" << endl;
            break;
        
        }
    handler_standard_input();
    return true;
}

bool Client::handler_list(){
    if(!_logged){
        cout << "You are not logged in !" << endl;
        return false;
    }
    string n_posts;
    int n;
    while (true) {
        cout << "How many posts do you want to see? " << endl;
        cin >> n_posts;
        try {
            n = stoi(n_posts);
            if (n >= 1 && n <= 9) {
                break;
            } else {
                cout << "Please enter a valid integer: [Range between 1 and 9]" << endl;
            }
        } catch (invalid_argument& e) {
            cout << "Please enter a valid integer: [Range between 1 and 9]" << endl;
        } catch (out_of_range& e) {
            cout << "Please enter a valid integer: [Range between 1 and 9]" << endl;
        }
        cin.clear();
        cin.ignore(numeric_limits<streamsize>::max(), '\n');
    }
    
    network_message message;
    
    message.nonce = _freshness;
    message.request = LIST_COMMAND;
    message.content_length = n_posts.length() + 1;
    message.content = n_posts;
 

    if(!send_auth_and_encrypted_message(sd, message, _session_key)){
        cout << "Error sending the message" << endl;
        return false;
    }

    network_message response;

    if(!receive_auth_and_encrypted_message(sd, response, _session_key)){
        cout << "Error receiving the message" << endl;
        return false;
    }
    if(response.request == LIST_COMMAND_ERROR){
        cout << "No post found!" << endl;
        _freshness++;
        return false;
    }
    
    if(response.request == SESSION_ERROR){
        cout << "Session error, possibly replay attack!" << endl;
        clean_client();
        return false;
    }
    if(response.request == SESSION_EXPIRED){
        cout << "Session expired, please login again!" << endl;
        clean_client();
        return false;
    }
    if(response.request == GENERIC_ERROR){
        cout << "An error has occurred, please login again!" << endl;
        clean_client();
        return false;
    }
    if(response.request == LIST_COMMAND_OK){
        _freshness++;
        vector<Post> list = StringToPosts(response.content);
        cout <<"Here the latest " << n << " posts: " << endl;
        showPosts(list);
    }
    handler_standard_input();
    return true;
}

bool Client::handler_get(){
    if(!_logged){
        cout << "You are not logged in !" << endl;
        return false;
    }
    string post_id;
    int id;
    while (true) {
        cout << "Enter the ID of the post you want to see: " << endl;
        cin >> post_id;
        try {
            id = stoi(post_id);
            if (id >= 1 && id <= MAX_POST_ID) {
                break;
            } else {
                cout << "Please enter a valid integer." << endl;
            }
        } catch (invalid_argument& e) {
            cout << "Please enter a valid integer." << endl;
        } catch (out_of_range& e) {
            cout << "Please enter a valid integer." << endl;
        }
        cin.clear();
        cin.ignore(numeric_limits<streamsize>::max(), '\n');
    }

    network_message message;
    message.nonce = _freshness;
    message.request = GET_COMMAND;
    message.content_length = post_id.length() + 1;
    message.content = post_id;

    if(!send_auth_and_encrypted_message(sd, message, _session_key)){
        cout << "Error sending the message" << endl;
        return false;
    }

    network_message response;

    if(!receive_auth_and_encrypted_message(sd, response, _session_key)){
        cout << "Error receiving the message" << endl;
        return false;
    }
    if(response.request == GET_COMMAND_ERROR){
        cout << "No post found" << endl;
        _freshness++;
        return false;
    }

    if(response.request == SESSION_ERROR){
        cout << "Session error, possibly replay attack!" << endl;
        clean_client();
        return false;
    }
    if(response.request == SESSION_EXPIRED){
        cout << "Session expired, please login again!" << endl;
        clean_client();
        return false;
    }
    if(response.request == GENERIC_ERROR){
        cout << "An error has occurred, please login again!" << endl;
        clean_client();
        return false;
    }
    if(response.request == GET_COMMAND_OK){
        vector<Post> list = StringToPosts(response.content);
        FILE *f = fopen("DataClient/downloaded_post.txt", "w");
        if(f == NULL){
            cout << "Error opening the file" << endl;
            return false;
        }
        cout << "The post has been downloaded in the file DataClient/downloaded_post.txt" << endl;
        for(size_t i = 0; i < list.size(); i++){
            fprintf(f, "----------------------\n");
            fprintf(f, "ID: %d\n", list[i].id);
            fprintf(f, "Title: %s\n", list[i].title.c_str());
            fprintf(f, "Author: %s\n", list[i].author.c_str());
            fprintf(f, "Body: %s\n", list[i].body.c_str());
        }
        fprintf(f, "----------------------\n");
        fclose(f);
        _freshness++;
    }
    handler_standard_input();
    return true;
}

bool Client::handler_add(){
    if(!_logged){
        cout << "You are not logged in !" << endl;
        return false;
    }
    string title,author,body;
    cout << "Enter the title of the post: " << endl;
    cin.ignore(numeric_limits<streamsize>::max(), '\n'); 
    getline(cin, title);
    cout << "Enter the author of the post: " << endl;
    getline(cin, author);
    cout << "Enter the body of the post: " << endl;
    getline(cin, body);

    network_message message;
    message.nonce = _freshness;
    message.request = ADD_COMMAND;
    message.content_length = title.length() + author.length() + body.length() + 3;
    message.content = title + "-" + author + "-" + body;

    if(!send_auth_and_encrypted_message(sd, message, _session_key)){
        cout << "Error sending the message" << endl;
        return false;
    }
    
    network_message response;

    if(!receive_auth_and_encrypted_message(sd, response, _session_key)){
        cout << "Error receiving the message" << endl;
        return false;
    }
    if(response.request == ADD_COMMAND_ERROR){
        cout << "Error adding the post" << endl;
        _freshness++;
        return false;
    }
    if(response.request == SESSION_ERROR){
        cout << "Session error, possibly replay attack!" << endl;
        clean_client();
        return false;
    }
    if(response.request == SESSION_EXPIRED){
        cout << "Session expired, please login again!" << endl;
        clean_client();
        return false;
    }
    if(response.request == GENERIC_ERROR){
        cout << "An error has occurred, please login again!" << endl;
        clean_client();
        return false;
    }
    if(response.request == ADD_COMMAND_OK){
        cout << "The post has been added" << endl;
        _freshness++;
    }
    handler_standard_input();
    return true;

}


bool Client::handler_logout(){
    if(!_logged){
        cout << "You are not logged in !" << endl;
        return false;
    }
    network_message message;
    message.nonce = _freshness;
    message.request = LOGOUT_COMMAND;
    message.content_length = 1;
    message.content = "0";

    if(!send_auth_and_encrypted_message(sd, message, _session_key)){
        cout << "Error sending the message" << endl;
        return false;
    }
    network_message response;

    if(!receive_auth_and_encrypted_message(sd, response, _session_key)){
        cout << "Error receiving the message" << endl;
        return false;
    }
    if(response.request == SESSION_ERROR){
        cout << "Session error, possibly replay attack!" << endl;
        clean_client();
        return false;
    }
    if(response.request == SESSION_EXPIRED){
        cout << "Session expired, please login again!" << endl;
        clean_client();
        return false;
    }
    if(response.request == LOGOUT_COMMAND_ERROR){
        cout << "An error has occurred !" << endl;
        clean_client();
        return false;
    }
    if(response.request == LOGOUT_COMMAND_OK){
        cout << "You have been logged out !" << endl;
        clean_client();
    }
    if(_command == "logout"){
        handler_standard_input();
    }
    else{
        return true;
    }
    return true;
}

int main() {
    Client client;
    client.print_dialog();
    client.handler_standard_input();
    return 0;
}