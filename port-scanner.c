/*
 * Concurrent TCP connect() scanner.
 *
 * Single-threaded: thousands of nonblocking connects are kept in flight at
 * once and epoll reports each one as it resolves.  A port is classified by
 * the real result of its connect, read back with getsockopt(SO_ERROR):
 *
 *   err == 0            -> open       (handshake completed)
 *   err == ECONNREFUSED -> closed     (RST: host reachable, nothing listening)
 *   deadline expires    -> filtered   (silently dropped, no reply at all)
 *
 * The filtered case is the reason for per-socket deadlines: a dropped SYN
 * produces no event ever, so only a timeout distinguishes it from a slow open.
 */

#define _POSIX_C_SOURCE 200112L

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define MAX_EVENTS 256
#define DEFAULT_WINDOW 1000
#define DEFAULT_TIMEOUT_MS 2000
#define FD_RESERVE 16 /* stdio + epoll fd + slack */

enum verdict { V_OPEN, V_CLOSED, V_FILTERED, V_NVERDICT };
static const char *verdict_name[] = {"open", "closed", "filtered"};

/* One in-flight connect.  Indexed by file descriptor: fds are small ints
 * bounded by RLIMIT_NOFILE, so the table doubles as the fd -> port map. */
struct conn {
  int in_use;
  int port;
  struct timespec deadline;
};

static struct conn *conns;
static int conns_len;
static int in_flight;
static long counts[V_NVERDICT];
static int show_all;

static void mono(struct timespec *ts) { clock_gettime(CLOCK_MONOTONIC, ts); }

static long ms_between(const struct timespec *from, const struct timespec *to) {
  return (to->tv_sec - from->tv_sec) * 1000L +
         (to->tv_nsec - from->tv_nsec) / 1000000L;
}

static void record(int port, enum verdict v) {
  counts[v]++;
  if (v == V_OPEN || show_all)
    printf("%5d/tcp  %s\n", port, verdict_name[v]);
}

/* Soft limit up to the hard limit; best effort, the hard cap needs root. */
static int raise_fd_limit(void) {
  struct rlimit rl;
  if (getrlimit(RLIMIT_NOFILE, &rl) != 0)
    return 256;
  if (rl.rlim_cur < rl.rlim_max) {
    rl.rlim_cur = rl.rlim_max;
    setrlimit(RLIMIT_NOFILE, &rl);
    if (getrlimit(RLIMIT_NOFILE, &rl) != 0)
      return 256;
  }
  return rl.rlim_cur > INT_MAX ? INT_MAX : (int)rl.rlim_cur;
}

static int resolve_host(const char *host, struct sockaddr_in *out) {
  struct addrinfo hints, *res;
  int rv;

  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;

  /* Resolved once for the whole scan; per port we only rewrite sin_port. */
  rv = getaddrinfo(host, NULL, &hints, &res);
  if (rv != 0) {
    fprintf(stderr, "getaddrinfo(%s): %s\n", host, gai_strerror(rv));
    return -1;
  }
  memcpy(out, res->ai_addr, res->ai_addrlen);
  freeaddrinfo(res);
  return 0;
}

static int parse_range(const char *s, int *lo, int *hi) {
  char *end;
  long a, b;

  errno = 0;
  a = strtol(s, &end, 10);
  if (errno != 0 || end == s || a < 1 || a > 65535)
    return -1;
  if (*end == '\0') {
    *lo = *hi = (int)a;
    return 0;
  }
  if (*end != '-')
    return -1;

  s = end + 1;
  errno = 0;
  b = strtol(s, &end, 10);
  if (errno != 0 || end == s || *end != '\0' || b < 1 || b > 65535 || b < a)
    return -1;

  *lo = (int)a;
  *hi = (int)b;
  return 0;
}

static void reap(int epfd, int fd) {
  epoll_ctl(epfd, EPOLL_CTL_DEL, fd, NULL);
  close(fd);
  conns[fd].in_use = 0;
  in_flight--;
}

/* 0 = handled (registered, or verdict already recorded)
 * -1 = out of descriptors, caller should shrink the window and retry
 * -2 = this port could not be attempted */
static int launch(int epfd, const struct sockaddr_in *base, int port,
                  int timeout_ms) {
  struct sockaddr_in addr = *base;
  struct epoll_event ev;
  int fd, flags;

  addr.sin_port = htons(port); /* host -> network byte order */

  fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0)
    return (errno == EMFILE || errno == ENFILE) ? -1 : -2;
  if (fd >= conns_len) { /* outside our table; treat as exhaustion */
    close(fd);
    return -1;
  }

  flags = fcntl(fd, F_GETFL, 0);
  if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
    close(fd);
    return -2;
  }

  /* Nonblocking connect returns immediately.  EINPROGRESS means the SYN is
   * on the wire and the verdict arrives later, via epoll. */
  if (connect(fd, (const struct sockaddr *)&addr, sizeof addr) == 0) {
    record(port, V_OPEN); /* instant completion, e.g. loopback */
    close(fd);
    return 0;
  }

  if (errno != EINPROGRESS) {
    record(port, errno == ECONNREFUSED ? V_CLOSED : V_FILTERED);
    close(fd);
    return 0;
  }

  memset(&ev, 0, sizeof ev);
  ev.events = EPOLLOUT; /* a pending connect completing makes fd writable */
  ev.data.fd = fd;
  if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev) < 0) {
    close(fd);
    return -2;
  }

  conns[fd].in_use = 1;
  conns[fd].port = port;
  mono(&conns[fd].deadline);
  conns[fd].deadline.tv_sec += timeout_ms / 1000;
  conns[fd].deadline.tv_nsec += (timeout_ms % 1000) * 1000000L;
  if (conns[fd].deadline.tv_nsec >= 1000000000L) {
    conns[fd].deadline.tv_sec++;
    conns[fd].deadline.tv_nsec -= 1000000000L;
  }
  in_flight++;
  return 0;
}

static void usage(const char *prog) {
  fprintf(stderr,
          "usage: %s <host> [lo-hi] [-t timeout_ms] [-w window] [-a]\n"
          "  -t  per-port timeout in ms (default %d)\n"
          "  -w  max connects in flight (default %d)\n"
          "  -a  print closed and filtered ports too\n",
          prog, DEFAULT_TIMEOUT_MS, DEFAULT_WINDOW);
}

int main(int argc, char **argv) {
  struct sockaddr_in base;
  struct epoll_event evs[MAX_EVENTS];
  struct timespec started, finished, now;
  const char *host = NULL;
  int lo = 1, hi = 65535;
  int timeout_ms = DEFAULT_TIMEOUT_MS;
  int window = DEFAULT_WINDOW;
  int fd_cap, epfd, next, i;

  for (i = 1; i < argc; i++) {
    if (strcmp(argv[i], "-t") == 0 && i + 1 < argc) {
      timeout_ms = atoi(argv[++i]);
      if (timeout_ms <= 0) { usage(argv[0]); return 1; }
    } else if (strcmp(argv[i], "-w") == 0 && i + 1 < argc) {
      window = atoi(argv[++i]);
      if (window <= 0) { usage(argv[0]); return 1; }
    } else if (strcmp(argv[i], "-a") == 0) {
      show_all = 1;
    } else if (argv[i][0] == '-' && argv[i][1] != '\0') {
      usage(argv[0]);
      return 1;
    } else if (host == NULL) {
      host = argv[i];
    } else if (parse_range(argv[i], &lo, &hi) != 0) {
      fprintf(stderr, "bad port range: %s\n", argv[i]);
      return 1;
    }
  }
  if (host == NULL) {
    usage(argv[0]);
    return 1;
  }

  if (resolve_host(host, &base) != 0)
    return 1;

  fd_cap = raise_fd_limit();
  if (window > fd_cap - FD_RESERVE)
    window = fd_cap - FD_RESERVE;
  if (window < 1)
    window = 1;

  conns_len = fd_cap;
  conns = calloc((size_t)conns_len, sizeof *conns);
  if (conns == NULL) {
    perror("calloc");
    return 1;
  }

  epfd = epoll_create1(0);
  if (epfd < 0) {
    perror("epoll_create1");
    free(conns);
    return 1;
  }

  printf("scanning %s ports %d-%d (window %d, timeout %dms)\n\n", host, lo, hi,
         window, timeout_ms);
  mono(&started);

  next = lo;
  while (next <= hi || in_flight > 0) {
    int wait_ms, n;
    long soonest = -1;

    /* Keep the window full.  The fd limit is what makes this necessary:
     * 65535 sockets at once is not an option. */
    while (in_flight < window && next <= hi) {
      int r = launch(epfd, &base, next, timeout_ms);
      if (r == -1) { /* descriptor exhaustion: back off, retry this port */
        if (window > 16)
          window /= 2;
        break;
      }
      if (r == -2)
        fprintf(stderr, "port %d: %s\n", next, strerror(errno));
      next++;
    }

    /* Sleep only until the earliest deadline, so filtered ports are noticed
     * promptly without busy-waiting. */
    if (in_flight > 0) {
      mono(&now);
      for (i = 0; i < conns_len; i++) {
        long ms;
        if (!conns[i].in_use)
          continue;
        ms = ms_between(&now, &conns[i].deadline);
        if (ms < 0)
          ms = 0;
        if (soonest < 0 || ms < soonest)
          soonest = ms;
      }
    }
    wait_ms = (soonest < 0) ? 0 : (int)soonest;

    n = epoll_wait(epfd, evs, MAX_EVENTS, wait_ms);
    if (n < 0) {
      if (errno == EINTR)
        continue;
      perror("epoll_wait");
      break;
    }

    for (i = 0; i < n; i++) {
      int fd = evs[i].data.fd;
      int err = 0;
      socklen_t len = sizeof err;

      if (fd < 0 || fd >= conns_len || !conns[fd].in_use)
        continue;

      /* Writability only means "resolved" -- success and failure both wake
       * epoll.  SO_ERROR is the only thing that says which. */
      if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len) < 0)
        err = errno;

      if (err == 0)
        record(conns[fd].port, V_OPEN);
      else if (err == ECONNREFUSED)
        record(conns[fd].port, V_CLOSED);
      else
        record(conns[fd].port, V_FILTERED);

      reap(epfd, fd);
    }

    /* Anything past its deadline never answered at all: filtered. */
    mono(&now);
    for (i = 0; i < conns_len; i++) {
      if (!conns[i].in_use)
        continue;
      if (ms_between(&now, &conns[i].deadline) <= 0) {
        record(conns[i].port, V_FILTERED);
        reap(epfd, i);
      }
    }
  }

  mono(&finished);

  /* Nothing should be left, but close defensively so no fd or byte leaks. */
  for (i = 0; i < conns_len; i++)
    if (conns[i].in_use)
      reap(epfd, i);

  close(epfd);
  free(conns);

  printf("\n%ld open, %ld closed, %ld filtered in %.2fs\n", counts[V_OPEN],
         counts[V_CLOSED], counts[V_FILTERED],
         ms_between(&started, &finished) / 1000.0);
  return 0;
}
