#include "md5util.h"
#include "md5/global.h"
#include "md5/md5.h"
#include <inttypes.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#define MAX_NUM_PASSWORDS 100

void compute_md5_checksum(struct ip *ip, struct tcphdr *tcp, char *password,
					 		uint8_t digest[16])
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
	MD5Update (&context, password, strlen(password));

    // Compute digest
    MD5Final (digest, &context);
}

struct pw_entry *pw_entries[MAX_NUM_PASSWORDS] = {NULL};

void load_passwords(char *filename) {
	const unsigned int MAX_LINE_LENGTH = 1000;
	char line[MAX_LINE_LENGTH];
	FILE *fp = fopen(filename, "r");

	struct pw_entry *entry;
	char app_address_str[16];
	char peer_address_str[16];
	char temp_password[MAX_LINE_LENGTH];
	int i;
	struct addrinfo *ai;
	struct addrinfo hints;
	int ret;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;

	if (fp == NULL) {
		fprintf(stderr, "Passwords file could not be opened.\n");
		exit(EXIT_FAILURE);
	}

	i = 0;
	while(fgets(line, MAX_LINE_LENGTH, fp) != NULL && i < MAX_NUM_PASSWORDS) {
		entry = (struct pw_entry *) malloc(sizeof(struct pw_entry));
		pw_entries[i] = entry;

		sscanf(line, "%s %hu %s %hu %s", app_address_str, 
				&(entry->app_port), peer_address_str, 
				&(entry->peer_port), temp_password);

		entry->password = (char *) malloc(strlen(temp_password)) + 1;
		strcpy(entry->password, temp_password);

		ret = getaddrinfo(app_address_str, NULL, &hints, &ai);
		if (ret) {
			fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(ret));
			exit(EXIT_FAILURE);
		}
		entry->app_address = ((struct sockaddr_in *)ai->ai_addr)
								->sin_addr.s_addr;
		freeaddrinfo(ai);

		ret = getaddrinfo(peer_address_str, NULL, &hints, &ai);
		if (ret) {
			fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(ret));
			exit(EXIT_FAILURE);
		}
		entry->peer_address = ((struct sockaddr_in *)ai->ai_addr)
								->sin_addr.s_addr;
		freeaddrinfo(ai);

		i++;
	}

	fclose(fp);
}

char * get_password(uint32_t app_address, uint16_t app_port, 
		uint32_t peer_address, uint16_t peer_port) {
	int i = 0;
	struct pw_entry *entry;
	while (i < MAX_NUM_PASSWORDS && (entry = pw_entries[i]) != NULL) {
		if (entry->app_address == app_address && 
				entry->app_port == app_port &&
				entry->peer_address == peer_address &&
				entry->peer_port == peer_port) {
			return entry->password; 
		} else if (entry->app_address == peer_address && 
				entry->app_port == peer_port &&
				entry->peer_address == app_address &&
				entry->peer_port == app_port) {
			return entry->password; 
		}

		i++;
	}

	fprintf(stderr, "Password could not be found %x:%hu to %x:%hu\n", 
			app_address, app_port, peer_address, peer_port);
	return NULL;
}
