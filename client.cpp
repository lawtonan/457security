#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <iostream>
#include <fstream>
#include <pthread.h>

bool running = true;

void* handleserver(void* arg) {
  int serversocket = *(int*)arg;
    while (running) {
        char line[5000] = "";

        recv(serversocket, line, 5000, 0);
        if (running) {
            std::cout << "\nGot from server: " << line << "\n";
        }

        if(strcmp(line, "Quit") == 0) {
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

    pthread_t child;
    pthread_create(&child,NULL,handleserver,&sockfd);
    pthread_detach(child);

	std::cout << "Commands\n";
	std::cout << "Send a Message to another client: \"Clientname\" \"Message\"\n";
	std::cout << "List clients connected: List\n";
	std::cout << "Kick a different client off: K\"Clientname\"\n";
	std::cout << "Disconnect Client: Quit\n";

    while (running) {
        char line[5000];

        
        std::cout << "Enter a Message: ";

        if (first == 1) {
            std::cin.ignore();
            first--;
        }
        std::cin.getline(line,5000);

        send(sockfd, line, strlen(line)+1, 0);

        if(strcmp(line, "Quit") == 0) {
            std::cout << "Exiting Client\n";
            return 1;
        }
    }

    return 0;
}
