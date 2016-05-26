#if !defined STATUSQ_H
#define STATUSQ_H

#if defined HAVE_STDINT_H
#include <stdint.h>
#endif
#include <sys/types.h>

#define FL_REQUEST		0x8000
#define FL_QUERY		0x7800
#define FL_NON_AUTH_ANSWER	0x0400
#define FL_DGRAM_NOT_TRUNCATED	0x0200
#define FL_RECURSION_NOT_DESIRED	0x0100
#define FL_RECURSION_NOT_AVAIl	0x0080
#define FL_RESERVED1		0x0040
#define FL_RESERVED2		0x0020
#define	FL_BROADCAST		0x0010
#define FL_SUCCESS		0x000F

#define	QT_NODE_STATUS_REQUEST	0x0021
#define QC_INTERNET		0x0001

#define NB_DGRAM		137

struct nbname {
	char ascii_name [16] ;
	my_uint16_t rr_flags;
};

struct nbname_request {
        my_uint16_t transaction_id;
        my_uint16_t flags;
        my_uint16_t question_count;
        my_uint16_t answer_count;
        my_uint16_t name_service_count;
        my_uint16_t additional_record_count;
        char question_name[34]; 
        my_uint16_t question_type;
        my_uint16_t question_class;
};

#define NBNAME_REQUEST_SIZE 50
#define UDP_HEADER_SIZE 8
#define IP_HEADER_SIZE 20

typedef struct nbname_response_header {
	my_uint16_t transaction_id;
	my_uint16_t flags;
	my_uint16_t question_count;
	my_uint16_t answer_count;
	my_uint16_t name_service_count;
	my_uint16_t additional_record_count;
	char question_name[34];
	my_uint16_t question_type;
	my_uint16_t question_class;
	my_uint32_t ttl;
	my_uint16_t rdata_length;
	my_uint8_t number_of_names;
} nbname_response_header_t;

/* #define NBNAME_RESPONSE_NUMBER_OF_NAMES_OFFSET 56 */

#define NBNAME_RESPONSE_HEADER_SIZE 57

typedef struct nbname_response_footer {
	my_uint8_t adapter_address [6];
	my_uint8_t version_major;
	my_uint8_t version_minor;
	my_uint16_t duration;
	my_uint16_t frmps_received;
	my_uint16_t frmps_transmitted;
	my_uint16_t iframe_receive_errors;
	my_uint16_t transmit_aborts;
	my_uint32_t transmitted;
	my_uint32_t received;
	my_uint16_t iframe_transmit_errors;
	my_uint16_t no_receive_buffer;
	my_uint16_t tl_timeouts;
	my_uint16_t ti_timeouts;
	my_uint16_t free_ncbs;
	my_uint16_t ncbs;
	my_uint16_t max_ncbs;
	my_uint16_t no_transmit_buffers;
	my_uint16_t max_datagram;
	my_uint16_t pending_sessions;
	my_uint16_t max_sessions;
	my_uint16_t packet_sessions;
} nbname_response_footer_t ;

#define NBNAME_RESPONSE_FOOTER_SIZE 50

struct nb_host_info {
	struct nbname_response_header* header;
	struct nbname* names;
	struct nbname_response_footer* footer;
	int is_broken;
};

typedef struct nb_service {
	char nb_name[16];
	my_uint8_t service_number;
	int unique;
	char* service_name;
} nb_service_t ;

#endif /* STATUSQ_H */
