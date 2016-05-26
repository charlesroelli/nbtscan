#include <stdio.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "range.h"
#include <string.h>
#include <stdlib.h>
#include "errors.h"

#ifndef INADDR_NONE
# define INADDR_NONE (in_addr_t)-1
#endif

extern int quiet;

/* is_ip checks if supplied string is an ip address in dotted-decimal
   notation, and fills both members of range structure with its numerical value
   (host byte order)/ Returns 1 on success, 0 on failure */
int is_ip(char* string, struct ip_range* range) {
	unsigned long addr;

	addr = inet_addr(string);
	if(addr != INADDR_NONE) {
		range->start_ip = ntohl(addr);
		range->end_ip	= ntohl(addr);
		return 1;
	} else return 0;
}; 

/* is_range1 checks if supplied string is an IP address range in
   form xxx.xxx.xxx.xxx/xx (as in 192.168.1.2/24) and fills
   range structure with start and end ip addresses of the interval.
   Returns 1 on success, 0 on failure */
int is_range1(char* string, struct ip_range* range) {
	char* separator;
	unsigned long mask;
	char* ip;

	if((ip = (char *)malloc(strlen(string)+1))==NULL) 
		err_die("Malloc failed", quiet);

	if (strlen(string)>19) return 0;
	if(separator=(char*)strchr(string,'/')) {
		separator++;
		mask=atoi(separator);
		if(mask<=0 || mask>32) return 0;
		strcpy(ip, string);
		ip[abs(string-separator)-1]=0;
		if((range->start_ip=inet_addr(ip)) == INADDR_NONE) return 0;
/*		mask=((1<<mask)-1)<<(sizeof(mask)*8-mask); */
		if (mask == 32)
			mask = ~0;
		else
			mask=((1<<mask)-1)<<(sizeof(mask)*8-mask);

		range->start_ip=ntohl(range->start_ip); // We store ips in host byte order
		range->start_ip &= mask;
		range->end_ip = range->start_ip | ( ~ mask);
		free(ip);
		return 1;
	}
	free(ip);
	return 0;
};


/* next_address function writes next ip address in range after prev_addr to
   structure pointed by next_addr. Returns 1 if next ip found and 0 otherwise */ 
int next_address(const struct ip_range* range, const struct in_addr* prev_addr, 
		 struct in_addr* next_addr) {
	unsigned long pa; // previous address, host byte order
	
	if(prev_addr) {
		pa = ntohl(prev_addr->s_addr);
		if(pa < range->end_ip) {
			next_addr->s_addr=htonl(++pa); 
			return 1;
		} else return 0;
	} else {
		next_addr->s_addr=htonl(range->start_ip);
		return 1;
	};
};
	
/* is_range2 checks if supplied string is an IP address range in
   form xxx.xxx.xxx.xxx-xxx (as in 192.168.1.2-15) and fills
   range structure with start and end ip addresses of the interval.
   Returns 1 on success, 0 on failure */
int is_range2(char* string, struct ip_range* range) {
	unsigned long last_octet; /*last octet of last ip in range*/
	char* separator;
	unsigned long addr;
	char* ip;

	if((ip = (char *)malloc(strlen(string)+1))==NULL) 
		err_die("Malloc failed", quiet);
	strcpy(ip,string);

	if(separator = (char*)strchr(ip,'-')) {
		*separator=0;
		separator++;
		last_octet = atoi(separator);
		if(last_octet<0 || last_octet > 255) {
			free(ip);
			return 0;
		};
		addr = inet_addr(ip);
		if(addr == INADDR_NONE) {
			free(ip);
			return 0;
		};
		range->start_ip = ntohl(addr);
		range->end_ip = (range->start_ip & 0xffffff00) | last_octet;
		if (range->end_ip < range->start_ip) { 
			free(ip);
			return 0;
		};
		free(ip);
		return 1;
	}
	free(ip);
	return 0;
};

int print_range(const struct ip_range* range) {
	struct in_addr *addr;
	
	if((addr = (struct in_addr*)malloc(sizeof(struct in_addr)))==NULL) 
		err_die("Malloc failed", quiet);
	
	next_address(range, 0, addr);
	printf("%s\n",inet_ntoa(*addr));
	
	while(next_address(range, addr, addr)) {
	        printf("%s\n",inet_ntoa(*addr));
	};
	free(addr);
};
