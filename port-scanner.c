#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

int main(void) {
  int sfd; // socket file descriptor
  int rv;
  const char *target = "scanme.nmap.org";
  struct addrinfo hints;
  struct addrinfo *servinfo;

  memset(&hints, 0, sizeof(hints)); // empty struct
  hints.ai_family = AF_INET;        // ipv4 or ipv6, dont care
  hints.ai_socktype = SOCK_STREAM;  // tcp

  // resolve once, NULL service->the result carries port 0, then we fill it in
  rv = getaddrinfo(target, NULL, &hints, &servinfo);
  if (rv != 0) {
    fprintf(stderr, "gai error %s\n", gai_strerror(rv));
    exit(1);
  }

  // our own copy of the address bytes to mutate
  struct sockaddr_in addr;
  memcpy(&addr, servinfo->ai_addr, servinfo->ai_addrlen);

  for (int i = 20; i < 25; i++) {
    addr.sin_port = htons(i);

    sfd = socket(servinfo->ai_family, servinfo->ai_socktype,
                 servinfo->ai_protocol);
    if (sfd == -1) {
      perror("socket");
      continue;
    }

    int c = connect(sfd, (struct sockaddr *)&addr, sizeof addr);

    if (c == -1) {
      if (errno == ECONNREFUSED) {
        printf("Port Number: %d Socket Closed\n", i);
      } else if (errno == EHOSTUNREACH) {
        printf("Port Number: %d Host is unreachable\n", i);
      } else if (errno == ENETUNREACH) {
        printf("Port Number: %d Network is unreachable\n", i);
      } else {
        printf("Port Number: %d Unknown Error\n", i);
        printf("%s\n", strerror(errno));
      }

    } else {
      printf("Port Number: %d Connected!\n", i);
    }

    close(sfd);
  }

  freeaddrinfo(servinfo);
}
