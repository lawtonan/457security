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


std::map<int, int> clientList;
std::map<int, unsigned char*> clientKeyList;

void* handleclient(void* arg) {
	
	int clientsocket = *(int*)arg;
	std::map<int,int>::iterator it;
	std::map<int, unsigned char*>::iterator it2;	
	
  	char privfilename[12] = "RSApriv.pem";
  	unsigned char iv[16];
	unsigned char iv2[16];
	unsigned char encrypted_key[256];
	unsigned char ciphertext[5000];
	int testr; 
	testr = recv(clientsocket, encrypted_key, 256, 0);
	std::cout << "Encrypted Key: " << encrypted_key << "\t" << testr << "\n";
	EVP_PKEY *privkey;
	
	FILE* privf = fopen(privfilename,"rb");
  	privkey = PEM_read_PrivateKey(privf,NULL,NULL,NULL);
	fclose(privf);
	unsigned char decrypted_key[32];
  	int decryptedkey_len = rsa_decrypt(encrypted_key, testr, privkey, decrypted_key); 
  	std::cout << "Decrypted Key: " << decrypted_key << "\t" << decryptedkey_len << "\n";
  	//decryptedtext_len = decrypt(ciphertext, ciphertext_len, decrypted_key, iv,
	//		      	decryptedtext);
  	//decryptedtext[decryptedtext_len] = '\0';
  	
  	unsigned char decryptedtext[5000];
  	int decryptedtext_len, ciphertext_len;
  	
  	std::cout << "GOTO WHILE\n";
  	int rsize;
  	
  	//RAND_bytes(key,32);
  	//RAND_bytes(iv,16);
	for (it = clientList.begin(); it != clientList.end(); ++it) {
		if(it->second == clientsocket){
			clientKeyList[it->first] = decrypted_key;
		}
	}

  	
    while (1) {
        unsigned char line[5000] = "";
	recv(clientsocket, iv, 64, 0);
	
	RAND_bytes(iv2,16);       

	std::cout << "IV: " << iv << "\t" << sizeof(iv) << "\n";
	rsize = recv(clientsocket, line, 5000, 0);

	std::cout << "message recieved: " << line << "\t" << rsize << "\n";
        std::cout << "\n\nGOT TO DECRYPT\n";



        decryptedtext_len = decrypt(line, rsize , decrypted_key, iv,
			      decryptedtext);
	std::cout << "GOT PAST DECRYPT\n";
  		decryptedtext[decryptedtext_len] = '\0';
        	
		std::cout << "Got from client: " << decryptedtext << "\n";

        if(strcmp((char*)decryptedtext, "List") == 0) {
          
          std::string s = "";

          for (it = clientList.begin(); it != clientList.end(); ++it) {
            s = s + std::to_string(it->first) + " ";
          }
	
	  for (it = clientList.begin(); it != clientList.end(); ++it) {
		for (it2 = clientKeyList.begin(); it2 != clientKeyList.end(); ++it){
			if(it->second == clientsocket && it-> first == it2-> first){
	  			ciphertext_len = encrypt ((unsigned char*)s.c_str(), strlen(s.c_str())+1, it2->second, iv2,ciphertext);	
			}
		}	
	  }
//------------------------------------------------------------------------------------
	  send(clientsocket, iv2 , 64, 0);			
          send(clientsocket, ciphertext, ciphertext_len, 0);
        }
        else if (decryptedtext[0] == '*') {
		for (it = clientList.begin(); it != clientList.end(); ++it) {
			for (it2 = clientKeyList.begin(); it2 != clientKeyList.end(); ++it){
          			if(it->second != clientsocket && it-> first == it2-> first){
					send(it->second, iv2 , 64, 0);
					ciphertext_len = encrypt (decryptedtext + 2, decryptedtext_len-1, it2->second, iv2,ciphertext);	
					send(it->second,ciphertext, ciphertext_len, 0);
				}
          		}
       		 }
	}
	else if (decryptedtext[0] == 'K') {
		unsigned char message[5000] = "Enter the password: ";
		unsigned char recPass[5000] = "";
		for (it = clientList.begin(); it != clientList.end(); ++it) {
			for (it2 = clientKeyList.begin(); it2 != clientKeyList.end(); ++it){
				if(it->second == clientsocket && it-> first == it2-> first){
					send(it->second, iv2 , 64, 0);					
					ciphertext_len = encrypt (message, strlen((char *)message), it2->second, iv2,
                          					ciphertext);
					send(it->second,ciphertext, ciphertext_len, 0);
					recv(clientsocket, iv, 64, 0);
					rsize = recv(it->second, recPass, 5000, 0);
					decryptedtext_len = decrypt(message, rsize , decrypted_key, iv,
			      					decryptedtext);
					if (strcmp((char*)decryptedtext, "123456") == 0) {
						int kill = (int)decryptedtext[1] - 48;
						send(it->second, iv2 , 64, 0);
						ciphertext_len = encrypt ((unsigned char*)"Quit", 4, clientKeyList[kill], iv2, ciphertext);
						send(clientList[kill], ciphertext, ciphertext_len, 0);
					}
				}
			}
		}
	}
	else if (strcmp((char*)decryptedtext, "Quit") == 0) {
		for (it = clientList.begin(); it != clientList.end(); ++it) {
			for (it2 = clientKeyList.begin(); it2 != clientKeyList.end(); ++it){
				if(it->second == clientsocket && it-> first == it2-> first){
					clientList.erase(it);
					clientKeyList.erase(it2);
				}
			}
		}
		EVP_cleanup();
  		ERR_free_strings();
		pthread_exit(0);
	}
        else {
			int sendto = (int)decryptedtext[0] - 48;
          	if (clientList.count(sendto)) {
			send(clientList[sendto], iv2 , 64, 0);
			ciphertext_len = encrypt (decryptedtext + 2, decryptedtext_len-1, clientKeyList[sendto], iv2,ciphertext);	
           		send(clientList[sendto],ciphertext, ciphertext_len, 0);
          	}
          	else
          	{
			unsigned char errmessage[22] = "Client does not exist";
			for (it = clientList.begin(); it != clientList.end(); ++it) {
				for (it2 = clientKeyList.begin(); it2 != clientKeyList.end(); ++it){
					if(it->second == clientsocket && it-> first == it2-> first){
						send(clientList[sendto], iv2 , 64, 0);
						ciphertext_len = encrypt (errmessage, 22, it2->second, iv2,ciphertext);
            					send(clientsocket, ciphertext, 22, 0);
					}
				}
			}
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
