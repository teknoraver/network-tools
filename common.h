#ifndef COMMON_H
#define COMMON_H

enum protocols {
	/* all */
	ALL,

	/* Ethernet */
	IPV4,
	IPV6,
	PPPOE,
	ARP,

	/* IP */
	ICMP,
	TCP,
	UDP,
	SCTP,
	_MAX_PROTO,
};

struct trafdata {
	uint64_t packets;
	uint64_t bytes;
};

#endif
