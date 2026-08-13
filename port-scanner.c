#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

int main(void) {
  int sfd; // socket file descriptor
  const char *localhost = "scanme.nmap.org";
  char str[6];
  struct addrinfo hints;
  struct addrinfo *servinfo;

  memset(&hints, 0, sizeof(hints)); // empty struct
  hints.ai_family = AF_INET;        // ipv4 or ipv6, dont care
  hints.ai_socktype = SOCK_STREAM;  // tcp

  for (int i = 8080; i < 8081; i++) {
    snprintf(str, sizeof(str), "%d", i);
    if ((sfd = getaddrinfo(localhost, str, &hints, &servinfo)) != 0) {
      fprintf(stderr, "Port Number: %d gai error: %s\n", i, gai_strerror(sfd));
      exit(1);
    }
    sfd = socket(servinfo->ai_family, servinfo->ai_socktype,
                 servinfo->ai_protocol);

    int c = connect(sfd, servinfo->ai_addr, servinfo->ai_addrlen);

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
    freeaddrinfo(servinfo);
  }
}
