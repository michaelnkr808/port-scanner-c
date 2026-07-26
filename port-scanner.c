#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

int main() {
  int sfd; // socket file descriptor
  struct addrinfo hints, *res;
  struct addrinfo *servinfo;

  memset(&hints, 0, sizeof(hints)); // empty struct
  hints.ai_family = AF_UNSPEC;      // ipv4 or ipv6, dont care
  hints.ai_socktype = SOCK_STREAM;  // tcp
  hints.ai_flags = AI_PASSIVE;

  if ((sfd = getaddrinfo(NULL, "3490", &hints, &servinfo)) != 0) {
    fprintf(stderr, "gai error: %s\n", gai_strerror(sfd));
    exit(1);
  }

  sfd = getaddrinfo("INPUT HOST HERE", "PORT", &hints, &servinfo);

  sfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);

  int c = connect(sfd, res->ai_addr, res->ai_addrlen);

  if (c == -1) {
    fprintf(stderr, "Connection Refused");
  } else {
    // here i implement sequential checking of ports
  }

  freeaddrinfo(servinfo);
}
