#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

int main(void) {
  int sfd; // socket file descriptor
  const char *localhost = "127.0.0.1";
  struct addrinfo hints;
  struct addrinfo *servinfo;

  memset(&hints, 0, sizeof(hints)); // empty struct
  hints.ai_family = AF_INET;        // ipv4 or ipv6, dont care
  hints.ai_socktype = SOCK_STREAM;  // tcp

  if ((sfd = getaddrinfo(localhost, "7000", &hints, &servinfo)) != 0) {
    fprintf(stderr, "gai error: %s\n", gai_strerror(sfd));
    exit(1);
  }

  sfd =
      socket(servinfo->ai_family, servinfo->ai_socktype, servinfo->ai_protocol);

  int c = connect(sfd, servinfo->ai_addr, servinfo->ai_addrlen);

  if (c == -1) {
    fprintf(stderr, "Connection Errored\n");
    printf("%s\n", strerror(errno));
  } else {
    printf("Okay nice you connected\n");
    // here i implement sequential checking of ports
  }

  freeaddrinfo(servinfo);
}
