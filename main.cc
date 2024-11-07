#include <iostream>

#include "icmp.h"

#include <netdb.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <error.h>
#include <sys/time.h>
#include <arpa/inet.h>

#define _PING_BUFLEN(p, u) ((u)? ((p)->ping_datalen + sizeof (struct icmp6_hdr)) : \
				   (MAXIPLEN + (p)->ping_datalen + ICMP_TSLEN))

struct timespec
current_timespec(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return ts;
}

typedef int (*ping_efp6)(int code, void *closure, struct sockaddr_in6 *dest,
                         struct sockaddr_in6 *from, struct icmp6_hdr *icmp,
                         int datalen);

typedef int (*ping_efp)(int code,
                        void *closure,
                        struct sockaddr_in *dest,
                        struct sockaddr_in *from,
                        struct ip *ip, icmphdr_t *icmp, int datalen);

union ping_address
{
    struct sockaddr_in ping_sockaddr;
    struct sockaddr_in6 ping_sockaddr6;
};

union event
{
    ping_efp6 handler6;
    ping_efp handler;
};

typedef struct ping_data PING;

struct ping_data
{
    int ping_fd;                     /* Raw socket descriptor */
    int ping_type;                   /* Type of packets to send */
    size_t ping_count;               /* Number of packets to send */
    struct timespec ping_start_time; /* Start time */
    size_t ping_interval;            /* Number of seconds to wait between sending pkts */
    union ping_address ping_dest;    /* whom to ping */
    char *ping_hostname;             /* Printable hostname */
    size_t ping_datalen;             /* Length of data */
    int ping_ident;                  /* Our identifier */
    union event ping_event;          /* User-defined handler */
    void *ping_closure;              /* User-defined data */

    /* Runtime info */
    int ping_cktab_size;
    char *ping_cktab;

    unsigned char *ping_buffer; /* I/O buffer */
    union ping_address ping_from;
    size_t ping_num_xmit; /* Number of packets transmitted */
    size_t ping_num_recv; /* Number of packets received */
    size_t ping_num_rept; /* Number of duplicates received */
};

int volatile stop = 0;
int ping_receive(PING *p);

void sig_int(int signal);
int send_echo(PING *ping);
int ping_xmit(PING *p);
int ping_set_dest (PING *ping, const char *host);

PING *ping;

int main()
{
    struct protoent *proto = getprotobyname("icmp");
    if (!proto)
    {
        fprintf(stderr, "ping: unkown protocol icmp.\n");
        return EXIT_FAILURE;
    }
    int fd = socket(AF_INET, SOCK_RAW, proto->p_proto);
    if (fd < 0)
    {
        fprintf(stderr, "ping: udp socket failed.\n");
        return EXIT_FAILURE;
    }

    ping = static_cast<PING *>(malloc(sizeof(*ping)));
    if (!ping)
    {
        close(fd);
        return EXIT_FAILURE;
    }
    memset(ping, 0, sizeof(*ping));
    ping->ping_fd = fd;
    ping->ping_type = ICMP_TIMESTAMP;
    ping->ping_count = 0;
    ping->ping_interval = 1000;
    ping->ping_datalen = ICMP_TSLEN;
    /* Make sure we use only 16 bits in this field, id for icmp is a unsigned short.  */
    ping->ping_ident = getpid() & 0xFFFF;
    ping->ping_cktab_size = 128;
    ping->ping_start_time = current_timespec();

    int one = 1;
    setsockopt(ping->ping_fd, SOL_SOCKET, SO_BROADCAST, (char *)&one, sizeof(one));

    /* Force line buffering regardless of output device.  */
    setvbuf(stdout, NULL, _IOLBF, 0);

    signal(SIGINT, sig_int);

    int fdmax;
    fdmax = ping->ping_fd + 1;

    timespec last = current_timespec();
    if (ping_set_dest (ping, "192.168.106.1"))
        error (EXIT_FAILURE, 0, "unknown host");

    send_echo(ping);

    // 添加 select 相关变量
    fd_set readset;
    struct timeval timeout;
    
    // 主循环监听
    while (!stop) {
        FD_ZERO(&readset);
        FD_SET(ping->ping_fd, &readset);
        
        // 设置超时为1秒
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;
        
        int ret = select(fdmax, &readset, NULL, NULL, &timeout);
        if (ret < 0) {
            if (errno == EINTR)
                continue;
            error(EXIT_FAILURE, errno, "select");
        }
        
        if (ret == 0) {
            // 超时，可以在这里处理
            continue;
        }
        
        if (FD_ISSET(ping->ping_fd, &readset)) {
            if (ping_receive(ping) < 0) {
                printf("接收错误\n");
            }
        }
    }

    // 清理资源
    free(ping->ping_buffer);
    free(ping->ping_cktab);
    free(ping);
    return 0;
}

void sig_int(int signal)
{
    stop = 1;
}

int send_echo(PING *ping)
{
    size_t off = 0;
    int rc;

    rc = ping_xmit(ping);
    if (rc < 0)
        error(EXIT_FAILURE, errno, "sending packet");

    return rc;
}

int ping_xmit(PING *p)
{
    int i, buflen;
    ping->ping_buffer = static_cast<unsigned char*>(malloc (_PING_BUFLEN (p, false)));
    if (!p->ping_buffer){
        error(EXIT_FAILURE, errno, "allocate ping_buffer");
    }
    p->ping_cktab = static_cast<char*>(malloc(p->ping_cktab_size));
    if (!p->ping_cktab){
      error(EXIT_FAILURE, errno, "allocate ping_cktab");
    }
    memset(p->ping_cktab, 0, p->ping_cktab_size);

    buflen = ICMP_TSLEN;

    /* Encode ICMP header */
    timeval tv;
    unsigned long v;

    gettimeofday (&tv, nullptr);
    v = htonl ((tv.tv_sec % 86400) * 1000 + tv.tv_usec / 1000);

    icmphdr_t *icmp = (icmphdr_t *)ping->ping_buffer;
    icmp->icmp_otime = v;
    icmp->icmp_rtime = v;
    icmp->icmp_ttime = v;

    icmp->icmp_type = ICMP_TIMESTAMP;
    icmp->icmp_code = 0;
    icmp->icmp_cksum = 0;
    icmp->icmp_seq = htons (0);
    icmp->icmp_id = htons (0);

    icmp->icmp_cksum = icmp_cksum (ping->ping_buffer, buflen);

    // 添加调试信息
    printf("p->ping_buffer content: ");
    for (int j = 0; j < buflen; j++)
    {
        printf("%02x ", ((unsigned char *)p->ping_buffer)[j]);
    }
    printf("\n");
    // 检查目标地址
    printf("Destination address: %s\n", inet_ntoa(p->ping_dest.ping_sockaddr.sin_addr));
    // 添加调试信息
    printf("Sending packet with fd: %d, buflen: %d\n", p->ping_fd, buflen);
    i = sendto(p->ping_fd, (char*)ping->ping_buffer, buflen, 0,
               (struct sockaddr *)&p->ping_dest.ping_sockaddr,
               sizeof(struct sockaddr_in));
    icmp->icmp_cksum = 0;
    icmp->icmp_seq = htons (0);
    icmp->icmp_id = htons (1);
    icmp->icmp_cksum = icmp_cksum (ping->ping_buffer, buflen);
    i = sendto(p->ping_fd, (char*)ping->ping_buffer, buflen, 0,
               (struct sockaddr *)&p->ping_dest.ping_sockaddr,
               sizeof(struct sockaddr_in));
    if (i < 0)
    {
        return -1;
    }
    else
    {
        p->ping_num_xmit++;
        if (i != buflen)
            printf("ping: wrote %s %d chars, ret=%d\n",
                   p->ping_hostname, buflen, i);
    }
    return 0;
}

int
ping_set_dest (PING *ping, const char *host)
{
  int rc;
  struct addrinfo hints, *res;
  char *rhost;

  rhost = NULL;


  memset (&hints, 0, sizeof (hints));
  hints.ai_family = AF_INET;
  hints.ai_flags = AI_CANONNAME;
# ifdef AI_IDN
  hints.ai_flags |= AI_IDN;
# endif
# ifdef AI_CANONIDN
  hints.ai_flags |= AI_CANONIDN;
# endif

  rc = getaddrinfo (host, NULL, &hints, &res);

  if (rc)
    {
      free (rhost);
      return 1;
    }

  memcpy (&ping->ping_dest.ping_sockaddr, res->ai_addr, res->ai_addrlen);
  if (res->ai_canonname)
    ping->ping_hostname = strdup (res->ai_canonname);
  else
    ping->ping_hostname = strdup (host);

  freeaddrinfo (res);

  return 0;
}

int ping_receive(PING *p)
{
    int n;
    socklen_t fromlen = sizeof(p->ping_from);
    struct ip *ip;
    icmphdr_t *icmp;
    int hlen = 0;
    
    // 分配接收缓冲区
    unsigned char buf[_PING_BUFLEN(p, false)];
    
    // 接收数据
    n = recvfrom(p->ping_fd, (char *)buf, sizeof(buf), 0,
                 (struct sockaddr *)&p->ping_from.ping_sockaddr, &fromlen);
    if (n < 0)
        return -1;

    // 获取IP头部
    ip = (struct ip *)buf;
    hlen = ip->ip_hl << 2;
    
    // 检查接收到的数据是否完整
    if (n < hlen + ICMP_MINLEN) {
        fprintf(stderr, "packet too short (%d bytes) from %s\n", n,
                inet_ntoa(p->ping_from.ping_sockaddr.sin_addr));
        return -1;
    }

    // 获取ICMP头部
    icmp = (icmphdr_t *)(buf + hlen);
    
    // 打印接收到的时间戳信息
    if (icmp->icmp_type == ICMP_TIMESTAMPREPLY) {
        struct timeval tv;
        gettimeofday(&tv, NULL);
        unsigned long now = htonl((tv.tv_sec % 86400) * 1000 + tv.tv_usec / 1000);
        
        printf("从 %s 收到时间戳回复\n", inet_ntoa(p->ping_from.ping_sockaddr.sin_addr));
        printf("ICMP ident: %d, seq: %d\n", ntohs(icmp->icmp_hun.ih_idseq.icd_id), ntohs(icmp->icmp_hun.ih_idseq.icd_seq));
        printf("发起时间戳: %lu\n", ntohl(icmp->icmp_otime));
        printf("接收时间戳: %lu\n", ntohl(icmp->icmp_rtime));
        printf("传输时间戳: %lu\n", ntohl(icmp->icmp_ttime));
        printf("当前时间戳: %lu\n", ntohl(now));
        
        p->ping_num_recv++;
    }
    
    return 0;
}
