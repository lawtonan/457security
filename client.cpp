#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <iostream>
#include <fstream>
#include <pthread.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>


bool running = true;

void handleErrors(void);
int rsa_encrypt(unsigned char* in, size_t inlen, EVP_PKEY *key, unsigned char* out);
//int rsa_decrypt(unsigned char* in, size_t inlen, EVP_PKEY *key, unsigned char* out);
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
	unsigned char *iv, unsigned char *ciphertext);
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
	    unsigned char *iv, unsigned char *plaintext);

struct params{
	int sockfd;
	unsigned char key[32];
};

void* handleserver(void* arg) {
	unsigned char iv2[16];
	struct params info = *(struct params*)arg;
  	int serversocket = info.sockfd;
	unsigned char key[32];
	memcpy(key,info.key,32);
  	int decryptedtext_len;
	int rsize;
    while (running) {
        unsigned char line[5000] = "";
	unsigned char decryptedtext[5000] = "";
	recv(serversocket, iv2, 64, 0);
        rsize = recv(serversocket, line, 5000, 0);
	std::cout << "TRY TO DECRYPT" << line << "\n";
	//decryptedtext_len = decrypt(line, rsize , key, iv2, decryptedtext);
        if (running) {
            std::cout << "\nGot from server: " << line << "\n";
        }

        if(strcmp((char*)decryptedtext, "Quit") == 0) {
            std::cout << "Exiting Client\n";
            running = false;
            send(serversocket, "Quit", 4, 0);
            pthread_exit(0);
        }
    }
    return 0;
}

int main(int arc, char** argv) {

    int sockfd = socket(AF_INET,SOCK_STREAM,0);
    if (sockfd < 0) {
        std::cout << "There was an error creating the socket\n";
        return 1;
    }

    char ipAddress[5000];
    int port;
    std::cout << "Enter an IP address: ";
    std::cin >> ipAddress;
    std::cout << "Enter a Port number: ";
    std::cin >> port;

    struct sockaddr_in serveraddr;
    serveraddr.sin_family=AF_INET;
    serveraddr.sin_port=htons(port);
    serveraddr.sin_addr.s_addr=inet_addr(ipAddress);

    int e = connect(sockfd, (struct sockaddr*)&serveraddr, sizeof(serveraddr));

    if (e<0){
        std::cout << "There was an error connecting\n";
        return 2;
    }

    std::cout << "Conected to server.\n\n";

    int first = 1;

    

	std::cout << "Commands\n";
	std::cout << "Send a Message to another client: \"Clientname\" \"Message\"\n";
	std::cout << "List clients connected: List\n";
	std::cout << "Kick a different client off: K\"Clientname\"\n";
	std::cout << "Disconnect Client: Quit\n";

	char pubfilename[11] = "RSApub.pem";
	//unsigned char *privfilename = "RSApriv.pem";
	unsigned char key[32];
	unsigned char iv[16];
	int ciphertext_len;

	OpenSSL_add_all_algorithms();
	EVP_PKEY *pubkey;
	
	RAND_bytes(key,32);
  	RAND_bytes(iv,16);

	struct params pass;
	pass.sockfd=sockfd;
	memcpy(pass.key,key,32);

	pthread_t child;
    	pthread_create(&child,NULL,handleserver,&pass);
    	pthread_detach(child);

	FILE* pubf = fopen(pubfilename,"rb");
	pubkey = PEM_read_PUBKEY(pubf,NULL,NULL,NULL);
	fclose(pubf);
	unsigned char encrypted_key[256];
	std::cout << "Decrypted Key: " << key << "\t" << sizeof(key) << "\n\n";
	int encryptedkey_len = rsa_encrypt(key, 32, pubkey, encrypted_key);
  	//ciphertext_len = encrypt (plaintext, strlen ((char *)plaintext), key, iv,
    //                        ciphertext);
	std::cout << "Encrypted Key: " << encrypted_key << "\t" << encryptedkey_len << "\n";
	send(sockfd, encrypted_key, encryptedkey_len, 0);
	
	unsigned char ciphertext[5000];



    while (running) {

		
  	RAND_bytes(iv,16);
	
	send(sockfd, iv , 64, 0);
	
        unsigned char line[5000];
	std::cout << "IV: " << iv << "\t" << sizeof(iv) << "\n";
        
        std::cout << "Enter a Message: ";

        if (first == 1) {
            std::cin.ignore();
            first--;
        }
        std::cin.getline((char*)line,5000);
	
	std::cout << "message recieved: " << line << "\t" << strlen ((char *)line) << "\n";
	
		//std::cout << "line is " << line << "\n";
		ciphertext_len = encrypt (line, strlen ((char *)line), key, iv,
                            ciphertext);
	
	std::cout << "message sent: " << ciphertext << "\t" << ciphertext_len << "\n";

        send(sockfd, ciphertext, ciphertext_len, 0);
		//std::cout << "cipher text is " << ciphertext << " cipher text size is " << ciphertext_len  << "----" << strlen ((char *)line) << "\n";
		//exit(1);
        if(strcmp((char*)line, "Quit") == 0) {
            std::cout << "Exiting Client\n";
            return 1;
        }
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

/*
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
*/

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
