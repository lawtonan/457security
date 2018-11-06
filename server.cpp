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

std::map<int, int> clientList;

void* handleclient(void* arg) {
	int clientsocket = *(int*)arg;
	std::map<int,int>::iterator it;
    while (1) {
        char line[5000] = "";
        recv(clientsocket, line, 5000, 0);
		std::cout << "Got from client: " << line << "\n";

        if(strcmp(line, "List") == 0) {
          //char line2[5000] = "";
          std::string s = "";

          for (it = clientList.begin(); it != clientList.end(); ++it) {
            s = s + std::to_string(it->first) + " ";
          }
          //strcpy(line2, s.c_str());
          send(clientsocket, s.c_str(), strlen(s.c_str())+1, 0);
        }
        else if (line[0] == '*') {
		  for (it = clientList.begin(); it != clientList.end(); ++it) {
          	if(it->second != clientsocket)
				send(it->second,line + 2, strlen(line)-1, 0);
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
			for (it = clientList.begin(); it != clientList.end(); ++it) {
				if(it->second == clientsocket){
					clientList.erase(it);
				}
			}
			pthread_exit(0);
		}
        else {
			int sendto = (int)line[0] - 48;
          	if (clientList.count(sendto)) {
           		send(clientList[sendto],line + 2, strlen(line)-1, 0);
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

    while(1){
        int len = sizeof(clientaddr);
        int clientsocket = accept(sockfd, (struct sockaddr*)&clientaddr, (socklen_t*)&len);
        
        pthread_t child;
        pthread_create(&child,NULL,handleclient,&clientsocket);
        pthread_detach(child);
	
		clientList[num_clients] = clientsocket;
        num_clients++;
    }
    return 0;
}
