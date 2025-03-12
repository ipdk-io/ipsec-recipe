// Copyright 2000-2002, 2004-2017, 2021-2023 Intel Corporation
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef IPSEC_OFFLOAD_H_
#define IPSEC_OFFLOAD_H_

#include <library.h>
#include <kernel/kernel_ipsec.h>
#include <../libstrongswan/ipsec/ipsec_types.h>

//#include <../libstrongswan/selectors/traffic_selector.h>

#define TEN_MS							10000
#define IPV6_LEN    					16
#define IPv4							0x4
#define IPv6							0x6
#define CRYPTO_SUCCESS					0x0
#define ARW_CHK_FAIL 					0x1
#define AUTH_CHK_FAIL 					0x2
#define SOFT_AGING_THRESHOLD_CROSSED	0x3
#define HARD_AGING_THRESHOLD_CROSSED	0x4
#define BAD_PKT							0x5
#define SEQ_NUM_ROLLOVER				0x6
#define INVALID_SA_INDEX				0x7
#define RESERVED						0x8

#define KEY_BUF_MAX 120

typedef struct ipsec_offload_t ipsec_offload_t;
typedef struct ipsec_offload_params_t ipsec_offload_params_t;
typedef struct ipsec_offload_basic_params_t ipsec_offload_basic_params_t;
typedef struct ipsec_offload_policy_t ipsec_offload_policy_t;

typedef struct ipsec_offload_traffic_selector_t ipsec_offload_traffic_selector_t;

typedef struct address_chunk_t address_chunk_t;
typedef struct ipsec_event_listener_t ipsec_event_listener_t;
struct address_chunk_t {
	int addr_family;
	size_t addr_len;
	char addr[16];
};	
struct ipsec_event_listener_t {

	/**
	 * Called when the lifetime of an IPsec SA expired
	 *
	 * @param protocol		protocol of the expired SA
	 * @param spi			spi of the expired SA
	 * @param dst			destination address of expired SA
	 * @param hard			TRUE if this is a hard expire, FALSE otherwise
	 */
	void (*expire)(uint8_t protocol, uint32_t spi, host_t *dst, bool hard);
};
/**
 * Private data of an traffic_selector_t object
 */
struct ipsec_offload_traffic_selector_t {

	/**
	 * Type of address
	 */
	ts_type_t type;

	/**
	 * IP protocol (UDP, TCP, ICMP, ...)
	 */
	uint8_t protocol;

	/**
	 * narrow this traffic selector to hosts external ip
	 * if set, from and to have no meaning until set_address() is called
	 */
	bool dynamic;

	/**
	 * subnet size in CIDR notation, 255 means a non-subnet address range
	 */
	uint8_t netbits;

	/**
	 * begin of address range, network order
	 */
	char from[IPV6_LEN];

	/**
	 * end of address range, network order
	 */
	char to[IPV6_LEN];

	/**
	 * begin of port range
	 */
	uint16_t from_port;

	/**
	 * end of port range
	 */
	uint16_t to_port;
};
/**
 * Implementation of the ipsec interface intel ipsec plugin
 */
struct ipsec_offload_t {

	/**
	 * Implements kernel_ipsec_t interface
	 */
	kernel_ipsec_t interface;
};
struct ipsec_offload_basic_params_t {
	address_chunk_t src;
	address_chunk_t dst;
	uint32_t	spi;
	uint32_t	offloadid; //This SA INDEX is the lower 3 bytes of RX SPI.
	bool	config_done;
};

struct ipsec_offload_policy_t {
	policy_dir_t 	dir;

	ipsec_offload_traffic_selector_t  	src_ts;
	ipsec_offload_traffic_selector_t  	dst_ts;

	ipsec_mode_t 	mode;
	uint32_t   spi;

};

struct ipsec_offload_params_t {
	ipsec_offload_basic_params_t	basic_params;
	ipsec_offload_policy_t		policy;
	uint32_t	replay_window;
	uint32_t	salt;
	uint16_t	enc_alg;
	uint8_t	proto;
	bool	esn;
	bool	inbound;
	size_t	key_len;
	char   key[KEY_BUF_MAX];
	lifetime_cfg_t	lifetime;
};

struct ipsec_offload_config_queue_data {
	uint8_t proto;
	uint8_t family;
	uint32_t spi;
	uint64_t cookie;
#define IP_BUF 16
	char sip[IP_BUF + 1];
	char dip[IP_BUF + 1];
};

/**
 * Create an ipsec offload interface instance.
 *
 * @return			ipsec_offload_t instance
 */
ipsec_offload_t *ipsec_offload_create();

#endif /** IPSEC_OFFLOAD_H_ @}*/
