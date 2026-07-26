#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

int main() {
  int sfd; // socket file descriptor
  struct addrinfo hints;
  struct addrinfo *servinfo;

  memset(&hints, 0, sizeof(hints)); // empty struct
  hints.ai_family = AF_UNSPEC;      // ipv4 or ipv6, dont care
  hints.ai_socktype = SOCK_STREAM;  // tcp

  if ((sfd = getaddrinfo(NULL, "3490", &hints, &servinfo)) != 0) {
    fprintf(stderr, "gai error: %s\n", gai_strerror(sfd));
    exit(1);
  }

  sfd =
      socket(servinfo->ai_family, servinfo->ai_socktype, servinfo->ai_protocol);

  int c = connect(sfd, servinfo->ai_addr, servinfo->ai_addrlen);

  if (c == -1) {
    fprintf(stderr, "Connection Errored");
  } else {
    // here i implement sequential checking of ports
  }

  freeaddrinfo(servinfo);
}
