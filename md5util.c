#include "md5util.h"
#include "md5/global.h"
#include "md5/md5.h"
#include <inttypes.h>
#include <string.h>
#include <stdio.h>

void compute_md5_checksum(struct ip *ip, struct tcphdr *tcp, uint8_t digest[16])
{
    MD5_CTX context;
    uint16_t sum;
    uint32_t *data;
    uint32_t data_len;

    MD5Init (&context);

    // TCP pseudo-header
    MD5Update (&context, &(ip->ip_src.s_addr), sizeof(ip->ip_src.s_addr));
    MD5Update (&context, &(ip->ip_dst.s_addr), sizeof(ip->ip_dst.s_addr));
    MD5Update (&context, &(ip->ip_p), sizeof(ip->ip_p)); //TODO: RFC says this needs to be 0 padded. To how many bytes?
    MD5Update (&context, &(ip->ip_len), sizeof(ip->ip_len));

    // TCP header
    sum = tcp->th_sum;
    tcp->th_sum = 0;
    MD5Update (&context, tcp, sizeof(*tcp));
    tcp->th_sum = sum;


    // TCP segment data
    data = (uint32_t*)(tcp)+tcp->th_off;
    data_len = ntohs(ip->ip_len) - ip->ip_hl*4 - tcp->th_off*4;
    MD5Update (&context, data, data_len);

    // Password
    MD5Update (&context, "password", strlen("password")); //TODO: read password from a file

    // Compute digest
    MD5Final (digest, &context);
}
