#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include "../../Tools/tools.h"
#define SIZE 1024

void get_file(char * filename){
  char file[50];
  printf("Enter the certificate file name to send: ");
  scanf("%s", file);
  // fgets(file, 50, stdin);
  strcpy(filename, file);
  filename[strlen(filename)] = 0;
}

void send_file(int sockfd){
  int n;
  FILE *fp;
  char *dir = "Certificates/";
  char cert_name[50];
  char filename[50];
  char data[SIZE] = {0};

  strcpy(filename, dir);
  get_file(cert_name);
  strcat(filename, cert_name);
  // printf("x%sx", filename);

  int length = strlen(cert_name);
  n = send(sockfd, &length, sizeof(int), 0);
  n = send(sockfd, cert_name, strlen(cert_name) * sizeof(char), 0);
  bzero(data, SIZE);
  if(n == -1){
      perror("[-]Error in sending file.");
      exit(1);
  }

  fp = fopen(filename, "r");
  if (fp == NULL) {
    printf("[-]Error in reading file: x%sx\n", filename);
    exit(1);
  }


  while(fgets(data, SIZE, fp) != NULL) {
    if (send(sockfd, data, sizeof(data), 0) == -1) {
      perror("[-]Error in sending file.");
      exit(1);
    }
    bzero(data, SIZE);
  }
}


int main(){
  char *ip = "0.0.0.0";
  int port = 8080;
  int e;

  int sockfd;
  struct sockaddr_in server_addr;
  FILE *fp;

  sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if(sockfd < 0) {
    perror("[-]Error in socket");
    exit(1);
  }
  printf("[+]Server socket created successfully.\n");

  server_addr.sin_family = AF_INET;
  server_addr.sin_port = port;
  server_addr.sin_addr.s_addr = inet_addr(ip);


int menu;
while(1){
    printf("Would you like to do?\n0.)generate keys\n1.)Create Cert\n2.)Validate Cert integrity\n3.)Populate a Cert Revocation List\n4.)Validate CRL\n5.)Validate certificate trust tree\n6.)Send a file\n7.)Exit\n");
    scanf("%d",&menu);
    if(menu==0)
    create_keys();
    if (menu==1)
    create_cert(); // trust level still needed as exit case for crl tree
    if(menu==2){
        char cert_file[50];
        printf(" PLEASE ENTER THE CERT FILE NAME:\n");
        scanf("%s",cert_file);
        validate_cert(cert_file);
    }
    if(menu==3)
        CRL_populate();
    if(menu == 4)
        CRL_validate();
    // if(menu == 5)
    //     tree_validate();
    if(menu == 6){
    e = connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr));
      if(e == -1) {
        perror("[-]Error in socket");
        exit(1);
      }
      printf("[+]Connected to Server.\n");
      send_file(sockfd);
      printf("[+]Certificate sent successfully.\n");
      printf("[+]Closing the connection.\n\n\n");
      close(sockfd);
    }
    if(menu == 7)
        break;

}
  return 0;
}