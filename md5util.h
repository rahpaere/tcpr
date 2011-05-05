#ifndef MD5UTIL_H
#define MD5UTIL_H

#include <netinet/tcp.h>
#include <netinet/ip.h>
#define PASSWORD_FILE "passwords.txt"

struct pw_entry {
	uint32_t app_address;
	uint16_t app_port;
	uint32_t peer_address;
	uint16_t peer_port;
	char *password;
};

void compute_md5_checksum(struct ip *ip, struct tcphdr *tcp, char *password,
						  uint8_t digest[16]);

void load_passwords(char *filename);

char * get_password(uint32_t app_address, uint16_t app_port, 
		uint32_t peer_address, uint16_t peer_port);

#endif
