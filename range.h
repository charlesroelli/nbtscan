#include <stdio.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#if !defined RANGE_H
#define RANGE_H

struct ip_range {
	unsigned long start_ip; // IP addresses in _host_ order, not network
        unsigned long end_ip;   
};

/* is_ip checks if supplied string is an ip address in dotted-decimal
   notation, and fills both members of range structure with its numerical value
   (host byte order)/ Returns 1 on success, 0 on failure */
int is_ip(char* string, struct ip_range* range); 

/* is_range1 checks if supplied string is an IP address range in
   form xxx.xxx.xxx.xxx/xx (as in 192.168.1.2/24) and fills
   range structure with start and end ip addresses of the interval.
   Returns 1 on success, 0 on failure */
int is_range1(char* string, struct ip_range* range);


/* next_address function writes next ip address in range after prev_addr to
   structure pointed by next_addr. Returns 1 if next ip found and 0 otherwise */ 
int next_address(const struct ip_range* range, const struct in_addr* prev_addr, 
		 struct in_addr* next_addr); 
	
/* is_range2 checks if supplied string is an IP address range in
   form xxx.xxx.xxx.xxx-xxx (as in 192.168.1.2-15) and fills
   range structure with start and end ip addresses of the interval.
   Returns 1 on success, 0 on failure */
int is_range2(char* string, struct ip_range* range);

int print_range(const struct ip_range* range); 

#endif /* RANGE_H */
