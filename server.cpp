#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <iostream>
#include <map>
#include <fstream>
#include <pthread.h>
#include <cstdio>
#include <bits/stdc++.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>

void handleErrors(void);
//int rsa_encrypt(unsigned char* in, size_t inlen, EVP_PKEY *key, unsigned char* out);
int rsa_decrypt(unsigned char* in, size_t inlen, EVP_PKEY *key, unsigned char* out);
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext);
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext);


std::map<int, std::pair<int,unsigned char*>> clientList;

void* handleclient(void* arg) {
    
    int clientsocket = *(int*)arg;
    std::map<int, std::pair<int,unsigned char*>>::iterator it;
    
    char pubfilename[11] = "RSApub.pem";
    char privfilename[12] = "RSApriv.pem";
    unsigned char key[32];
    unsigned char iv[16];
    unsigned char iv2[16];
    unsigned char encrypted_key[256];
    int testr; 
    testr = recv(clientsocket, encrypted_key, 256, 0);
    //std::cout << "Encrypted Key: " << encrypted_key << "\t" << testr << "\n";
    EVP_PKEY *privkey;
    
    FILE* privf = fopen(privfilename,"rb");
    privkey = PEM_read_PrivateKey(privf,NULL,NULL,NULL);
    fclose(privf);
    unsigned char decrypted_key[32];
    int decryptedkey_len = rsa_decrypt(encrypted_key, testr, privkey, decrypted_key); 
    //std::cout << "Decrypted Key: " << decrypted_key << "\t" << decryptedkey_len << "\n";
    //decryptedtext_len = decrypt(ciphertext, ciphertext_len, decrypted_key, iv,
    //		      	decryptedtext);
    //decryptedtext[decryptedtext_len] = '\0';
    
    
    int decryptedtext_len;
    
    //std::cout << "GOTO WHILE\n";
    int rsize;
    
    for (it = clientList.begin(); it != clientList.end(); ++it) {
        if(it->second.first == clientsocket){
            it->second.second = decrypted_key;
        }
    }
    //RAND_bytes(key,32);
    //RAND_bytes(iv,16);
    int ciphertext_len;
    unsigned char ciphertext[5000];
    
    while (1) {
        RAND_bytes(iv2,16);
        unsigned char line[5000] = "";
        unsigned char decryptedtext[5000] = "";
        recv(clientsocket, iv, 64, 0);
        
        //std::cout << "IV: " << iv << "\t" << sizeof(iv) << "\n";
        rsize = recv(clientsocket, line, 5000, 0);
        usleep(250);
        //std::cout << "message recieved: " << line << "\t" << rsize << "\n";
        //std::cout << "\n\nGOT TO DECRYPT\n";
        
        
        
        decryptedtext_len = decrypt(line, rsize , decrypted_key, iv,
                                    decryptedtext);
        //std::cout << "GOT PAST DECRYPT\n";
        decryptedtext[decryptedtext_len] = '\0';
        
        std::cout << "Got from client: " << decryptedtext << "\n";
        
        if(strcmp((char*)decryptedtext, "List") == 0) {
            
            std::string s = "";
            
            for (it = clientList.begin(); it != clientList.end(); ++it) {
                s = s + std::to_string(it->first) + " ";
            }
            for (it = clientList.begin(); it != clientList.end(); ++it) {
                //std::cout << "GOT HERE\n";
                char cstr[s.size()+1];
                strcpy(cstr, s.c_str());
                cstr[s.size()] = '\0';
                if(it->second.first == clientsocket){
                    //std::cout << "GOT HERE 1\n";
                    send(it->second.first, iv2 , 64, 0);
                    //std::cout << "GOT HERE 2\n";
                    ciphertext_len = encrypt ((unsigned char*)cstr, strlen((char *)cstr), it->second.second, iv2, ciphertext);
                    //std::cout << "GOT HERE 3\n";
                    send(it->second.first,ciphertext, ciphertext_len, 0);
                }
            }
            
            //send(clientsocket, s.c_str(), strlen(s.c_str())+1, 0);
        }
        else if (decryptedtext[0] == '*') {
            for (it = clientList.begin(); it != clientList.end(); ++it) {
                if(it->second.first != clientsocket){
                    send(it->second.first, iv2 , 64, 0);
                    ciphertext_len = encrypt ((unsigned char*)decryptedtext + 2, decryptedtext_len-1, it->second.second, iv2, ciphertext);
                    send(it->second.first,ciphertext, ciphertext_len, 0);
                }          
            }
        }
        else if (decryptedtext[0] == 'K') {
            for (it = clientList.begin(); it != clientList.end(); ++it) {
                if(it->second.first == clientsocket){
                    char message[21] = "Enter the password: ";
                    char pass[5000] = "";
                    send(it->second.first, iv2 , 64, 0);
                    ciphertext_len = encrypt ((unsigned char*)message, 21, it->second.second, iv2, ciphertext);
                    send(it->second.first,ciphertext, ciphertext_len, 0);
                    recv(clientsocket, iv, 64, 0);
                    rsize = recv(clientsocket, pass, 5000, 0);
                    usleep(250);
                    int kill = (int)decryptedtext[1] - 48;
                    decryptedtext_len = decrypt((unsigned char*)pass, rsize , decrypted_key, iv,
                                                decryptedtext);
                    decryptedtext[decryptedtext_len] = '\0';
                    std::cout << "Got Password: " << decryptedtext << "\n";
                    memcpy(pass,(char*)decryptedtext,decryptedtext_len+1);
                    if (strcmp(pass, "123456") == 0) {
                        
                        
                        
                        char qMessage[5] = "Quit";
                        
                        send(clientList[kill].first, iv2 , 64, 0);
                        ciphertext_len = encrypt ((unsigned char*)qMessage, 5, clientList[kill].second, iv2, ciphertext);
                        send(clientList[kill].first, ciphertext, ciphertext_len, 0);
                        std::cout << "Leaving:\n";
                    }
                }
            }
        }
        else if (strcmp((char*)decryptedtext, "Quit") == 0) {
            for (it = clientList.begin(); it != clientList.end(); ++it) {
                if(it->second.first == clientsocket){
                    clientList.erase(it);
                }
            }
            EVP_cleanup();
            ERR_free_strings();
            pthread_exit(0);
        }
        else {
            int sendto = (int)decryptedtext[0] - 48;
            if (clientList.count(sendto)) {
                send(clientList[sendto].first, iv2 , 64, 0);
                ciphertext_len = encrypt ((unsigned char*)decryptedtext + 2, decryptedtext_len-1, clientList[sendto].second, iv2, ciphertext);
                send(clientList[sendto].first,ciphertext, ciphertext_len, 0);
            }
            else
            {
                std::cout << "Client does not exist\n";
                //send(clientsocket, "Client does not exist", 22, 0);
            }
        }          
    }
    return 0;
}


int main(int arc, char** argv) {
    int sockfd = socket(AF_INET,SOCK_STREAM,0);
    
    if (sockfd<0) {
        std::cout << "Problem creating socket\n";
        return 1;
    }
    
    int port;
    std::cout << "Input a port number: ";
    std::cin >> port;
    
    struct sockaddr_in serveraddr, clientaddr;
    serveraddr.sin_family=AF_INET;
    serveraddr.sin_port=htons(port);
    serveraddr.sin_addr.s_addr=INADDR_ANY;
    
    int b = bind(sockfd, (struct sockaddr*)&serveraddr, sizeof(serveraddr));
    
    if(b<0) {
        std::cout << "Bind error\n";
        return 3;
    }
    listen(sockfd,10);
    
    int first = 1;
    int num_clients = 0;
    
    OpenSSL_add_all_algorithms();
    
    while(1){
        int len = sizeof(clientaddr);
        int clientsocket = accept(sockfd, (struct sockaddr*)&clientaddr, (socklen_t*)&len);
        
        pthread_t child;
        pthread_create(&child,NULL,handleclient,&clientsocket);
        pthread_detach(child);
        
        clientList[num_clients].first = clientsocket;
        num_clients++;
    }
    EVP_cleanup();
    ERR_free_strings();
    return 0;
}

void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

/*
 * int rsa_encrypt(unsigned char* in, size_t inlen, EVP_PKEY *key, unsigned char* out){ 
 *  EVP_PKEY_CTX *ctx;
 *  size_t outlen;
 *  ctx = EVP_PKEY_CTX_new(key, NULL);
 *  if (!ctx)
 *    handleErrors();
 *  if (EVP_PKEY_encrypt_init(ctx) <= 0)
 *    handleErrors();
 *  if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
 *    handleErrors();
 *  if (EVP_PKEY_encrypt(ctx, NULL, &outlen, in, inlen) <= 0)
 *    handleErrors();
 *  if (EVP_PKEY_encrypt(ctx, out, &outlen, in, inlen) <= 0)
 *    handleErrors();
 *  return outlen;
 * }
 */

int rsa_decrypt(unsigned char* in, size_t inlen, EVP_PKEY *key, unsigned char* out){ 
    EVP_PKEY_CTX *ctx;
    size_t outlen;
    ctx = EVP_PKEY_CTX_new(key,NULL);
    if (!ctx)
        handleErrors();
    if (EVP_PKEY_decrypt_init(ctx) <= 0)
        handleErrors();
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
        handleErrors();
    if (EVP_PKEY_decrypt(ctx, NULL, &outlen, in, inlen) <= 0)
        handleErrors();
    if (EVP_PKEY_decrypt(ctx, out, &outlen, in, inlen) <= 0)
        handleErrors();
    return outlen;
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext){
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;
    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
            }
            
            int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
                        unsigned char *iv, unsigned char *plaintext){
                EVP_CIPHER_CTX *ctx;
                int len;
                int plaintext_len;
                if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();
                if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
                    handleErrors();
                if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
                    handleErrors();
                plaintext_len = len;
                if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleErrors();
                plaintext_len += len;
                EVP_CIPHER_CTX_free(ctx);
                return plaintext_len;
                        }
                        
