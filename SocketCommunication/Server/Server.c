#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "../../Tools/tools.h"
#define SIZE 1024
char filename[SIZE];
  char cert_name[50];

void write_file(int sockfd){
  int n, length;
  FILE *fp;
  char buffer[SIZE];
  n = recv(sockfd, &length, sizeof(int), 0);
  n = recv(sockfd, buffer, length * sizeof(char), 0);
  strcpy(cert_name, buffer);
  strcpy(filename, "Certificates/");
  strcat(filename, cert_name);
  printf("Received certificate: %s\n", cert_name);


  fp = fopen(filename, "w+");
  bzero(buffer, SIZE);
  while (1) {
    n = recv(sockfd, buffer, SIZE, 0);
    if (n <= 0){
      break;
      return;
    }
    fprintf(fp, "%s", buffer);
    bzero(buffer, SIZE);
  }
  fclose(fp);
  return;
}

int main(){
  char *ip = "0.0.0.0";
  int port = 8080;
  int e;

  int sockfd, new_sock;
  struct sockaddr_in server_addr, new_addr;
  socklen_t addr_size;
  char buffer[SIZE];

  sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if(sockfd < 0) {
    perror("[-]Error in socket");
    exit(1);
  }
  printf("[+]Server socket created successfully.\n");

  server_addr.sin_family = AF_INET;
  server_addr.sin_port = port;
  server_addr.sin_addr.s_addr = inet_addr(ip);

  e = bind(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr));
  if(e < 0) {
    perror("[-]Error in bind");
    exit(1);
  }
  printf("[+]Binding successfull.\n");


  // if(cert_name[0] == 'C' && cert_name[1] == 'R' && cert_name[2] == 'L')
  //     CRL_validate();
  // else
  //     validate_cert(cert_name);

  int menu = 0;
  

  while(true){
  printf("What would you like to do with this file?\n");
    printf("1.)Validate Cert integrity\n2.)Validate CRL\n3.)Validate certificate trust tree\n4.)Receive a file\n5.)Exit\n");
    scanf("%d",&menu);
      if(menu==1)
          validate_cert(cert_name);
      if(menu == 2)
          CRL_validate();
      // if(menu == 3)
      //     tree_validate();
      if(menu == 4){
            if(listen(sockfd, 10) == 0){
          printf("[+]Listening....\n");
          }else{
          perror("[-]Error in listening");
              exit(1);
          }
          addr_size = sizeof(new_addr);
          new_sock = accept(sockfd, (struct sockaddr*)&new_addr, &addr_size);

          write_file(new_sock);
          printf("[+]Certificate received successfully.\n\n\n");
      }
      if(menu == 5)
          break;
  }
  remove("hash.txt");



  return 0;
}