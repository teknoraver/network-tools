#ifndef COMMON_H
#define COMMON_H

enum protocols {
	INVALID,
	/* all */
	ALL,
	BROADCAST,

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
	__u64 packets;
	__u64 bytes;
};

#endif
