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

std::map<int, int> clientList;

void* handleclient(void* arg) {
	
	int clientsocket = *(int*)arg;
	std::map<int,int>::iterator it;
	
	unsigned char *pubfilename = "RSApub.pem";
  	unsigned char *privfilename = "RSApriv.pem";
  	unsigned char key[32];
  	unsigned char iv[16];
	unsigned char encrypted_key[256];
	recv(clientsocket, encrypted_key, 256, 0);
	
	EVP_PKEY *privkey;
	
	FILE* privf = fopen(privfilename,"rb");
  	privkey = PEM_read_PrivateKey(privf,NULL,NULL,NULL);
	
	unsigned char decrypted_key[32];
  	int decryptedkey_len = rsa_decrypt(encrypted_key, encryptedkey_len, privkey, decrypted_key); 
  
  	//decryptedtext_len = decrypt(ciphertext, ciphertext_len, decrypted_key, iv,
	//		      	decryptedtext);
  	//decryptedtext[decryptedtext_len] = '\0';
  	char line[5000] = "";
  	unsigned char decryptedtext[5000];
  	char message[5000];
  	
    while (1) {
        line = "";
        recv(clientsocket, line, 5000, 0);
        
        decryptedtext_len = decrypt(line, strlen(line)+1 , decrypted_key, iv,
			      decryptedtext);
  		decryptedtext[decryptedtext_len] = '\0';
        
		std::cout << "Got from client: " << decryptedtext << "\n";

        if(strcmp(decryptedtext, "List") == 0) {
          
          std::string s = "";

          for (it = clientList.begin(); it != clientList.end(); ++it) {
            s = s + std::to_string(it->first) + " ";
          }
          send(clientsocket, s.c_str(), strlen(s.c_str())+1, 0);
        }
        else if (decryptedtext[0] == '*') {
		  for (it = clientList.begin(); it != clientList.end(); ++it) {
          	if(it->second != clientsocket)
				send(it->second,decryptedtext + 2, strlen(decryptedtext)-1, 0);
          }
        }
		else if (decryptedtext[0] == 'K') {
			message = "Enter the password: ";
			send(clientsocket, message, strlen(message)+1, 0);
			recv(clientsocket, message, 5000, 0);
			if (strcmp(message, "123456") == 0) {
				int kill = (int)decryptedtext[1] - 48;
				send(clientList[kill], "Quit", 4, 0);
			}
		}
		else if (strcmp(decryptedtext, "Quit") == 0) {
			for (it = clientList.begin(); it != clientList.end(); ++it) {
				if(it->second == clientsocket){
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
           		send(clientList[sendto],decryptedtext + 2, strlen(decryptedtext)-1, 0);
          	}
          	else
          	{
            	send(clientsocket, "Client does not exist", 22, 0);
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
	
		clientList[num_clients] = clientsocket;
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
int rsa_encrypt(unsigned char* in, size_t inlen, EVP_PKEY *key, unsigned char* out){ 
  EVP_PKEY_CTX *ctx;
  size_t outlen;
  ctx = EVP_PKEY_CTX_new(key, NULL);
  if (!ctx)
    handleErrors();
  if (EVP_PKEY_encrypt_init(ctx) <= 0)
    handleErrors();
  if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
    handleErrors();
  if (EVP_PKEY_encrypt(ctx, NULL, &outlen, in, inlen) <= 0)
    handleErrors();
  if (EVP_PKEY_encrypt(ctx, out, &outlen, in, inlen) <= 0)
    handleErrors();
  return outlen;
}
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
