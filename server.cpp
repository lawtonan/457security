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

bool running = true;
std::map<int, int> clientList;
std::map<int,int>::iterator it;

void* handleclient(void* arg) {
	int clientsocket = *(int*)arg;
    while (running) {
        char line[5000] = "";
        //char line2[5000];
        recv(clientsocket, line, 5000, 0);

        if(strcmp(line, "List") == 0) {
          std::cout << "Got List\n";
          char line2[5000] = "";
          std::string s = "";

          for (it = clientList.begin(); it != clientList.end(); ++it) {
            s = s + std::to_string(it->first) + " Socket: " + std::to_string(it->second);
          }
          strcpy(line2, s.c_str());
          send(clientsocket, line2, strlen(line2)+1, 0);
        }
        else if (line[0] == '*') {
          for (int i = 0; i < clientList.size(); i++) {
            if (clientList[i] != clientsocket) {
              send(clientList[i], line, strlen(line)+1, 0);
            }
          }
        }
				else if (line[0] == 'K') {
					char message[5000] = "Enter the password: ";
					send(clientsocket, message, strlen(message)+1, 0);
					recv(clientsocket, message, 5000, 0);
					if (strcmp(message, "123456") == 0) {
						int kill = (int)line[1] - 48;
						send(clientList[kill], "Quit", 4, 0);
					}
				}
				else if (strcmp(line, "Quit") == 0) {
					std::cout << "Pre clientList Size: " << clientList.size();
					for (int i = clientList.begin()->first; i < clientList.size(); i++) {
						if (clientList[i] == clientsocket) {
							it = clientList.find(i);
							clientList.erase(it);
						}
						std::cout << "clientList Size: " << clientList.size();
					}
					pthread_exit(0);
				}
        else { //Send to specfic int
					int sendto = (int)line[0] - 48;
          if (clientList.count(sendto)) {
            send(clientList[sendto], line, strlen(line)+1, 0);
          }
          else
          {
            send(clientsocket, "Client does not exist", 22, 0);
          }
        }
        if(running) {
            std::cout << "Got from client: " << line << "\n";
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

    while(running){
        int len = sizeof(clientaddr);
        //std::cout << "Got here\n";
        int clientsocket = accept(sockfd, (struct sockaddr*)&clientaddr, (socklen_t*)&len);
        

        pthread_t child;
        pthread_create(&child,NULL,handleclient,&clientsocket);
        pthread_detach(child);
	
	std::cout << "PThread Created\n";

	clientList[num_clients] = clientsocket;
        num_clients++;

        // char line[5000];
        // std::cout << "Enter a Message: ";
        // if (first == 1) {
        //     std::cin.ignore();
        //     first--;
        // }
        // std::cin.getline(line,5000);
        //
        // if(!running) {
        //     break;
        // }
        //
        // send(clientsocket, line, strlen(line)+1, 0);
        //
        // if(strcmp(line, "Quit") == 0) {
        //     std::cout << "Exiting Server\n";
        //     return 1;
        // }

    }


    return 0;
}
