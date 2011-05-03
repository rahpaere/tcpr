#ifndef MD5UTIL_H
#define MD5UTIL_H

#include <netinet/tcp.h>
#include <netinet/ip.h>

void compute_md5_checksum(struct ip *ip, struct tcphdr *tcp, uint8_t digest[16]);

#endif
