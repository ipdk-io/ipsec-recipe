/******************************************************************
 ******************************************************************
 * Copyright (C) 2000-2002, 2004-2017, 2021-2024 Intel Corporation.
 *
 *This file is part of ipsec-offload plugin from strongswan.
 *This program is free software; you can redistribute it and/or 
 *modify it under the
 *terms of the GNU General Public License as published by the
 *Free Software Foundation, either version 3 of the License, or
 *(at your option) any later version.

 *This program is distributed in the hope that it will be useful,
 *but WITHOUT ANY WARRANTY; without even the implied warranty of
 *MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *GNU General Public License for more details.
 
 *You should have received a copy of the GNU General Public License.
 *If not, see <https://www.gnu.org/licenses/>.
 **********************************************************************
 **********************************************************************/

#include "ipsec_offload.h"
#include <library.h>
#include <daemon.h>
#include <threading/mutex.h>
#include <utils/debug.h>
#include <pthread.h>
#include <unistd.h>
#include <stdio.h>
#include <linux/xfrm.h>

#include <collections/hashtable.h>
#ifdef ENABLEGRPC
#include "ipsec_grpc_connect.h"
#endif

#define DEBUG_PLUGIN 1

#define PROTO_BYTES_MAX 2000
#define CONFIG_DATA_MAX 5000
#define REQID_BIT_ARRAY_SIZE 1024

static bool subscribe_audit_done;
static int sub_done = 0;
static uint32_t reqid_bit[REQID_BIT_ARRAY_SIZE];

typedef struct private_ipsec_offload_t private_ipsec_offload_t;
enum ipsec_status gnmi_init();
enum ipsec_status p4rt_init();
enum ipsec_status ipsec_fetch_spi(uint32_t *);
enum ipsec_status ipsec_sa_add(char *buf);
enum ipsec_status ipsec_sa_del(int offloadid, bool inbound);
enum ipsec_status ipsec_subscribe_audit_log();
enum ipsec_status ipsec_fetch_audit_log(char *cq_data, int size);
enum ipsec_status ipsec_set_pipe(void);
enum ipsec_status ipsec_tx_spd_table(enum ipsec_table_op table_op,
						char dst_ip_addr[16],
						char  mask[16],
						uint32_t match_priority);
enum ipsec_status ipsec_spd_table(enum ipsec_table_op table_op,
                                                char dst_ip_addr[16],
                                                uint8_t proto,
						uint32_t offload_id);
enum ipsec_status ipsec_tx_sa_classification_table(enum ipsec_table_op table_op,
						char outer_dst_ip_addr[16],
						char outer_src_ip_addr[16],
						char dst_ip_addr[16],
						char src_ip_addr[16],
						char crypto_offload,
						uint32_t offloadid,
						uint32_t tunnel_id,
						uint8_t proto,
						bool tunnel_mode,
						bool is_underlay);
enum ipsec_status ipsec_rx_sa_classification_table(enum ipsec_table_op table_op,
						char dst_ip_addr[16],
						char src_ip_addr[16],
						uint32_t spi,
						uint32_t offloadid);
enum ipsec_status ipsec_rx_post_decrypt_table(enum ipsec_table_op table_op,
						char crypto_offload,
						char crypto_status,
						uint16_t crypt_tag,
						char src_ip_addr[16],
						char dst_ip_addr[16],
						uint32_t mod_blob_ptr);
enum ipsec_status ipsec_outer_ipv4_encap_mod_table(enum ipsec_table_op table_op,
						uint32_t mod_blob_ptr,
						char src_ip_addr[16],
						char dst_ip_addr[16],
						uint32_t proto,
						char smac[16],
						char dmac[16]);
enum ipsec_status ipsec_outer_ipv4_decap_mod_table(
						enum ipsec_table_op table_op,
						uint32_t mod_blob_ptr,
						char inner_smac[16],
						char inner_dmac[16]);
enum ipsec_status ipsec_tunnel_id_table(enum ipsec_table_op table_op,
                                        uint32_t tunnel_id);
#define SPI_MAX_LIMIT 0xffffff

#define PROTO_IP 4

struct private_ipsec_offload_t {

	/**
	 * Public ipsec_offload interface
	 */
	ipsec_offload_t public;

	/**
	 * Listener for lifetime expire events
	 */
	ipsec_event_listener_t ipsec_listener;

	/**
	 * Mutex to lock access to various lists
	 */
	mutex_t *mutex;

	/**
	 * RNG used to generate SPIs
	 */

	rng_t *rng;
	/**
	 * Socket used to communicate with P4SDE
	 */
	int socket;

	/**
	 * thread used to communicate with P4SDE for auto config msg
	 */
	pthread_t thread_id;

	/**
	 * flag to use with multi-threading
	 */
	bool close;

	/**
	 * Hash table of installed policies (ipsec_offload_params_t)
	 */
	hashtable_t *ipsec_offload_params;
};

typedef struct entry_selector_t entry_selector_t;

/**
 * Select hash entry based on these params.
 */
struct entry_selector_t {
	char src[IPV6_LEN];
	char dst[IPV6_LEN];
	uint32_t reqid;
};

typedef struct param_entry_t param_entry_t;

/**
 * IPsec offload param entry.
 */
struct param_entry_t {
	/**
	 * This will be used to store key params for hash table entry.
	 */
	entry_selector_t sel;

	/**
	 * This will be used to store inbound/outbound offloadid.
	 */
	uint32_t offload_id;
};

/**
 * Set the reqid bit for active IPsec connection
 */
static bool reqid_bitset(uint32_t reqid)
{
	if (reqid > REQID_BIT_ARRAY_SIZE)
		return false;
	return reqid_bit[reqid/32] |= 1 << (reqid%32);
}

/**
 * reset the reqid bit for active IPsec connection
 */
static bool reqid_bitclear(uint32_t reqid)
{
	if (reqid > REQID_BIT_ARRAY_SIZE)
		return false;
	return reqid_bit[reqid/32] &= ~(1 << (reqid%32));
}

/**
 * Check if IPsec connection is active
 */
static bool reqid_bitget(uint32_t reqid)
{
	if (reqid > REQID_BIT_ARRAY_SIZE)
		return false;
	return ( (reqid_bit[reqid/32] & (1 << (reqid%32) )) != 0 );
}

/**
 * Expiration callback
 */
static void expire(uint8_t protocol, uint32_t spi, host_t *dst, bool hard)
{
	charon->kernel->expire(charon->kernel, protocol, spi, dst, hard);
}

/**
 * prepare the key buffer in hex string format like "29:3a:3f:00....."
 */
static inline int pack_key(char *src, char *dst, int len)
{
    const char * hex = "0123456789ABCDEF";
    int i;

    for (i = 0; i < len - 1; i++) {
        *dst++ = hex[(*src>>4)&0xF];
        *dst++ = hex[(*src++)&0xF];
        *dst++ = ':';

    }
    *dst++ = hex[(*src>>4)&0xF];
    *dst++ = hex[(*src)&0xF];
    *dst = 0;

    return 0;
}

/**
 * Hash function for param_entry_t objects
 */
static u_int param_hash(param_entry_t *key)
{
	chunk_t chunk = chunk_from_thing(key->sel);
	return chunk_hash(chunk);
}

/**
 * Equality function for param_entry_t objects
 */
static bool param_equals(param_entry_t *key, param_entry_t *other_key)
{
	return memeq(key->sel.src, other_key->sel.src, IPV6_LEN) &&
	       memeq(key->sel.dst, other_key->sel.dst, IPV6_LEN) &&
	       key->sel.reqid == other_key->sel.reqid;
}

/**
 * prepare the proto_bytes buffer for SA.
 */
static void get_proto_bytes(uint32_t offload_id, kernel_ipsec_sa_id_t *id, kernel_ipsec_add_sa_t *data, char *proto_bytes)
{
	uint16_t enc_alg;
	char     key[KEY_BUF_MAX] = {0};
	uint64_t soft_life;

	/* ICE support AES GCM (0) and GMAC (1) mode, filling ipsec params accordingly
	 * TODO: need to move it to cypto_mgr
	 */
	if (data->enc_alg == 0x14)
		enc_alg = 0;
	else
		enc_alg = 1;

	pack_key(data->enc_key.ptr, key, data->enc_key.len);
	soft_life = data->lifetime->bytes.life - data->lifetime->bytes.jitter;

	snprintf(proto_bytes, PROTO_BYTES_MAX-1, "offload_id:%d,\ndirection:%d,\nreq_id:%d,\n"
						"spi:%u,\next_seq_num:%d,\nanti_replay_window_size:%d,\n"
						"protocol_parameters:%d,\nmode:%d,\n"
						"esp_payload {\nencryption {\nencryption_algorithm:%d,\nkey:\"%s\",\nkey_len:%d,\n}\n},\n"
						"sa_hard_lifetime {\nbytes:%llu\n},\nsa_soft_lifetime {\nbytes: %llu\n}\n",
						offload_id, data->inbound, 2, ntohl(id->spi), data->esn, data->replay_window,
						0, 0, enc_alg, key, data->enc_key.len, data->lifetime->bytes.life,
						soft_life);
}

static void fill_entry_selector(entry_selector_t *sel,
				kernel_ipsec_sa_id_t *id, kernel_ipsec_add_sa_t *data)
{
	chunk_t src = chunk_empty;
	chunk_t dst = chunk_empty;

	src = id->src->get_address(id->src);
	dst = id->dst->get_address(id->dst);
	explicit_bzero(sel, sizeof(*sel));
	sel->reqid = data->reqid;

	/* Inbound and outboud flow has single entry so prepare entry selector accordingly */
	if (data->inbound) {
		memcpy(sel->src, src.ptr, src.len);
		memcpy(sel->dst, dst.ptr, dst.len);
	} else {
		memcpy(sel->src, dst.ptr, src.len);
		memcpy(sel->dst, src.ptr, dst.len);
	}
}

static void fill_entry_selector_policy(entry_selector_t *sel,
				       kernel_ipsec_policy_id_t *id,
				       kernel_ipsec_manage_policy_t *data)
{
	chunk_t ts_src = chunk_empty;
	chunk_t ts_dst = chunk_empty;

	ts_src = data->src->get_address(data->src);
	ts_dst = data->dst->get_address(data->dst);
	explicit_bzero(sel, sizeof(*sel));
	sel->reqid = data->sa->reqid;

	/* Inbound and outboud flow has single entry so prepare entry selector accordingly */
	if (id->dir == POLICY_OUT) {
		memcpy(sel->src, ts_dst.ptr, ts_src.len);
		memcpy(sel->dst, ts_src.ptr, ts_dst.len);
	} else {
		memcpy(sel->src, ts_src.ptr, ts_src.len);
		memcpy(sel->dst, ts_dst.ptr, ts_dst.len);
	}
}

#ifdef DEBUG_PLUGIN
static void print_policy_id_data(kernel_ipsec_policy_id_t *id, kernel_ipsec_manage_policy_t *data)
{
	chunk_t ts_src_outer = chunk_empty;
	chunk_t ts_dst_outer = chunk_empty;
	chunk_t src = chunk_empty;
	chunk_t dst = chunk_empty;
	int i;

	src = id->src_ts->get_from_address(id->src_ts);
	dst = id->dst_ts->get_from_address(id->dst_ts);
	ts_src_outer = data->src->get_address(data->src);
	ts_dst_outer = data->dst->get_address(data->dst);

	DBG2(DBG_KNL," ======= id and data for policy ========= \n");

	DBG2(DBG_KNL,"src.len=%d", src.len);
	for (i = 0; i < src.len; i++)
		DBG2(DBG_KNL,"%d", src.ptr[i]);

	DBG2(DBG_KNL,"dst.len=%d", dst.len);
	for (i = 0; i < dst.len; i++)
		DBG2(DBG_KNL,"%d", dst.ptr[i]);

	DBG2(DBG_KNL,"ts_src_outer.len=%d", ts_src_outer.len);
	for (i = 0; i < ts_src_outer.len; i++)
		DBG2(DBG_KNL,"%d", ts_src_outer.ptr[i]);

	DBG2(DBG_KNL,"dst.len=%d", ts_dst_outer.len);
	for (i = 0; i < ts_dst_outer.len; i++)
		DBG2(DBG_KNL,"%d", ts_dst_outer.ptr[i]);

	DBG2(DBG_KNL,"data.reqid=%d", data->sa->reqid);

	DBG2(DBG_KNL," =======id data for policy done ========= \n");
}

static void print_sa_id_data(kernel_ipsec_sa_id_t *id, kernel_ipsec_add_sa_t *data)
{
	chunk_t src = chunk_empty;
	chunk_t dst = chunk_empty;
	int i;

	src = id->src->get_address(id->src);
	dst = id->dst->get_address(id->dst);

	DBG2(DBG_KNL,"\n =======add SA id data========= ");

	DBG2(DBG_KNL,"src.len=%d", src.len);
	for (i = 0; i < src.len; i++)
		DBG2(DBG_KNL,"%d", src.ptr[i]);

	DBG2(DBG_KNL,"dst.len=%d", dst.len);
	for (i = 0; i < dst.len; i++)
		DBG2(DBG_KNL,"%d", dst.ptr[i]);

	DBG2(DBG_KNL,"data.reqid=%d", data->reqid);

	DBG2(DBG_KNL," =======add SA id data done ========= \n");
}
#endif

static void logs(struct ipsec_offload_config_queue_data *hdr) {
	DBG2(DBG_KNL, "ipsec:: spi: 0x%x\n", hdr->spi);
	char *fmt;
	if (hdr->cookie == ARW_CHK_FAIL) {
		fmt = "arw check fail:: cookie: 0x%lx\n";
	} else if (hdr->cookie == AUTH_CHK_FAIL) {
		fmt = "auth check fail:: cookie: 0x%lx\n";
	} else if (hdr->cookie == BAD_PKT) {
		fmt = "bad pkt:: cookie: 0x%lx\n";
	} else if (hdr->cookie == SEQ_NUM_ROLLOVER) {
		fmt = "seq num rollover:: cookie: 0x%lx\n";
	} else if (hdr->cookie == INVALID_SA_INDEX) {
		fmt = "invalid sa index:: cookie: 0x%lx\n";
	} else {
		fmt = "reserved:: cookie: 0x%lx\n";
	}

	DBG2(DBG_KNL, fmt, hdr->cookie);
}

static void process_expire(struct ipsec_offload_config_queue_data *hdr)
{
	uint8_t protocol;
	uint32_t spi;
	host_t *dst;
	int family;
	bool hard;

	protocol = hdr->proto;
	spi = htonl(hdr->spi);
	family = (hdr->family == IPv4 ? AF_INET : (hdr->family == IPv6 ? AF_INET6 : AF_UNSPEC));
	hard = (hdr->cookie == HARD_AGING_THRESHOLD_CROSSED ? true : false);

	if (protocol == IPPROTO_ESP)
	{
		dst = host_create_from_string_and_family(hdr->dip, family, 0);
		if (dst)
		{
			DBG2(DBG_KNL, "received a XFRM_MSG_EXPIRE");
			expire(protocol, spi, dst, hard);
			dst->destroy(dst);
			DBG2(DBG_KNL, "XFRM_MSG_EXPIRE processed successfully");
		}
	}
	else
	{
		logs(hdr);
	}
}

static int fill_config_data(struct ipsec_offload_config_queue_data *data, char *buf)
{
   int proto, family;
   char* rest = buf;
   int soft_expire;
   char* token;

    while ((token = strtok_r(rest, ",", &rest))) {
	char* key = strtok(token, ":");
	char* value = strtok(NULL, ":");

	if (!strcmp("ipsec-sa-spi", key))
		sscanf(value, "%u", &data->spi);
	else if (!strcmp(" soft-lifetime-expire", key)) {
		sscanf(value, "%d", &soft_expire);
		if (soft_expire)
			data->cookie = SOFT_AGING_THRESHOLD_CROSSED;
		else
			data->cookie = HARD_AGING_THRESHOLD_CROSSED;
	}
	else if (!strcmp(" ipsec-sa-protocol", key)) {
		sscanf(value, "%d", &proto);
		data->proto = proto;
	}
	else if (!strcmp(" ipsec-sa-dest-address", key))
		sscanf(value, "%s", data->dip);
	else if (!strcmp(" address-family", key)) {
		sscanf(value, "%d", &family);
		if (family == 1)
			data->family = IPv4;
		else
			data->family = IPv6;
	}
	else
		return -1;
    }
    return 0;
}

void *audit_log_poll(void *arg) {
	pthread_detach(pthread_self());
	struct ipsec_offload_config_queue_data cfg_data;
	char config_data_buf[CONFIG_DATA_MAX];

	while (1) {
		if (*(bool *)arg == true) {
			pthread_exit(NULL);
		}

		/* TODO: initialize auto config is enabled by ipsec_fetch_spi()
		 * enable it using ipsec_subscribe_audit_log() and remove this check.
		 */
		if (!subscribe_audit_done) {
			DBG2(DBG_KNL, "subscribe to audit log notification not done!\n");
			sleep(1);
			continue;
		}
		if (!sub_done) {
			if (ipsec_subscribe_audit_log() == IPSEC_FAILURE) {
				DBG2(DBG_KNL,"Inline_crypto_ipsec audit log subscribe failed :: [%s] \n", __func__);
				sleep(1);
			} else {
				sub_done = 1;
				DBG2(DBG_KNL, "subscribe to audit log notification done\n");
			}
		}

		int ret = ipsec_fetch_audit_log(config_data_buf, CONFIG_DATA_MAX);
		DBG2(DBG_KNL, "ipsec_fetch_audit_log: ret=%d\n", ret);

		if(ret != IPSEC_FAILURE)
		{
			if (!fill_config_data(&cfg_data, config_data_buf)) {
				DBG1(DBG_KNL, "audit_log data= spi=%u:proto=%d:dip=%s:family=%d:cookie=%d\n",
				     cfg_data.spi, cfg_data.proto, cfg_data.dip, cfg_data.family, cfg_data.cookie);
				cfg_data.sip[IP_BUF] = '\0';
				process_expire(&cfg_data);
			}
		}
	}
	return NULL;
}

static void ipsec_auto_config_init(pthread_t *tid, bool *flag) {
	int err = pthread_create(tid, NULL, audit_log_poll, flag);
	if(err == IPSEC_FAILURE)
	{
		DBG2(DBG_KNL,"Inline_crypto_ipsec audit log thread creation failed :: [%s] \n", __func__);
		return;
	}

	return;
}

METHOD(kernel_ipsec_t, get_features, kernel_feature_t,
	private_ipsec_offload_t *this)
{
#if 0
	return KERNEL_REQUIRE_UDP_ENCAPSULATION | KERNEL_ESP_V3_TFC;
#endif
}

METHOD(kernel_ipsec_t, get_spi, status_t,
	private_ipsec_offload_t *this, host_t *src, host_t *dst,
	uint8_t protocol, uint32_t *spi)
{
	DBG1(DBG_KNL, "entring %s\n", __func__);
	this->mutex->lock(this->mutex);
	
	if(ipsec_set_pipe() == IPSEC_FAILURE)
	{
		this->mutex->unlock(this->mutex);
		DBG1(DBG_KNL, "Unable to set pipe\n");
	//	return FAILED;
	}
	if (ipsec_fetch_spi(spi) == IPSEC_FAILURE)
	{
		this->mutex->unlock(this->mutex);
		DBG1(DBG_KNL, "Unable to fetch spi from server\n");
		return FAILED;
	}
	DBG2(DBG_KNL, "allocated SPI %.8x", ntohl(*spi));
	subscribe_audit_done = 1;
	this->mutex->unlock(this->mutex);

	return SUCCESS;
}

METHOD(kernel_ipsec_t, get_cpi, status_t,
	private_ipsec_offload_t *this, host_t *src, host_t *dst,
	uint16_t *cpi)
{
	return SUCCESS;
}

METHOD(kernel_ipsec_t, add_sa, status_t,
	private_ipsec_offload_t *this, kernel_ipsec_sa_id_t *id,
	kernel_ipsec_add_sa_t *data)
{
	param_entry_t *param_entry = NULL, *current_entry = NULL;
	char proto_bytes[PROTO_BYTES_MAX] = {0};
	param_entry_t entry_key;
	uint32_t offload_id;

	DBG2(DBG_KNL,"add SA for inbound=%d ", data->inbound);
#ifdef DEBUG_PLUGIN
	print_sa_id_data(id, data);
#endif
	/*According to MEV ICE HAS pages ICE supports AES GCM/GMAC 128/256 algos only.
	 * Adding a proper validation for these 2 algos. */
	if((data->enc_alg != 0x14) && (data->enc_alg != 0x15)) {
		DBG1(DBG_KNL,"[%s]: Unsupported encryption algo = %x \n", __func__, data->enc_alg);
		return FAILED;
	}
	if((data->enc_key.len != 20) && (data->enc_key.len != 36)) {
		DBG1(DBG_KNL,"[%s]: Unsupported key length = %d \n", __func__, data->enc_key.len);
		return FAILED;
	}

	fill_entry_selector(&entry_key.sel, id, data);

	this->mutex->lock(this->mutex);
	current_entry = this->ipsec_offload_params->get(this->ipsec_offload_params, &entry_key);

	if(data->inbound == true) {
		entry_selector_t *sel;
		DBG2(DBG_KNL," :: [%s]for in_bound \n", __func__);
		if (current_entry) {
			DBG1(DBG_KNL,"[%s]: Already an entry \n", __func__);
			this->mutex->unlock(this->mutex);
			return FAILED;
		}
		offload_id = (0x00FFFFFF & ntohl(id->spi));
		INIT(param_entry,
			.offload_id = offload_id,
		);
		sel = &(param_entry->sel);
		fill_entry_selector(sel, id, data);
		DBG2(DBG_KNL,"add SA inbound: saving the entry in table");
		this->ipsec_offload_params->put(this->ipsec_offload_params, param_entry, param_entry);
	} else {
		DBG2(DBG_KNL,":: [%s]for out_bound \n", __func__);
		if (current_entry) {
			offload_id = current_entry->offload_id;
			DBG2(DBG_KNL,"add SA outbound got offload id=%d", offload_id);
		} else {
			DBG1(DBG_KNL,"[%s]: outbound: corresponding inbound not found!! \n", __func__);
			this->mutex->unlock(this->mutex);
			return FAILED;
		}
	}
	this->mutex->unlock(this->mutex);

	get_proto_bytes(offload_id, id, data, proto_bytes);
	if (ipsec_sa_add(proto_bytes) == IPSEC_SUCCESS) {
		DBG1(DBG_KNL, "SA Add Success for inbound=%d\n", data->inbound);
	} else {
		DBG1(DBG_KNL, "SA Add failed for inbound=%d\n", data->inbound);
		this->ipsec_offload_params->remove(this->ipsec_offload_params, current_entry);
		return FAILED;
	}

	DBG2(DBG_KNL,"TEMP: add SA with SA proto_bytes=%s\n", proto_bytes);
	explicit_bzero(proto_bytes, PROTO_BYTES_MAX);

	return SUCCESS;
}

METHOD(kernel_ipsec_t, update_sa, status_t,
	private_ipsec_offload_t *this, kernel_ipsec_sa_id_t *id,
	kernel_ipsec_update_sa_t *data)
{
	return SUCCESS;
}

METHOD(kernel_ipsec_t, query_sa, status_t,
	private_ipsec_offload_t *this, kernel_ipsec_sa_id_t *id,
	kernel_ipsec_query_sa_t *data, uint64_t *bytes, uint64_t *packets,
	time_t *time)
{
	return SUCCESS;
}

METHOD(kernel_ipsec_t, del_sa, status_t,
	private_ipsec_offload_t *this, kernel_ipsec_sa_id_t *id,
	kernel_ipsec_del_sa_t *data)
{
	return SUCCESS;
}

METHOD(kernel_ipsec_t, flush_sas, status_t,
	private_ipsec_offload_t *this)
{
	return SUCCESS;
}


METHOD(kernel_ipsec_t, add_policy, status_t,
	private_ipsec_offload_t *this, kernel_ipsec_policy_id_t *id,
	kernel_ipsec_manage_policy_t *data)
{
	param_entry_t  *current_entry = NULL;
	chunk_t ts_src_outer = chunk_empty;
	chunk_t ts_dst_outer = chunk_empty;
	char src_outer[IPV6_LEN] = {0};
	char dst_outer[IPV6_LEN] = {0};
	chunk_t ts_src = chunk_empty;
	chunk_t ts_dst = chunk_empty;
	char src[IPV6_LEN] = {0};
	char dst[IPV6_LEN] = {0};
	char to[IPV6_LEN] = {0};
	uint32_t spi, offload_id;
	char mac_mask[16] = {0};
	host_t *net_host;
	uint8_t netbits;
	char mask[16];
	int  err;

	char inner_smac[16] = {0x00, 0x01, 0x00, 0x00, 0x03, 0x14};
	char inner_dmac[16] = {0x84, 0x16, 0x0c, 0xba, 0x90, 0xf0};
	DBG2(DBG_KNL,"ADD Policy dir=%d START\n", id->dir);
#ifdef DEBUG_PLUGIN
	print_policy_id_data(id, data);
#endif
	/* The policy comes as Rx followed by Tx,
	 * And always (SA ADD,Policy ADD),(SA Delete,Policy Delete)
	 * are called together for a single session
	 * for eg if we have a session for TCP, a session for UDP,
	 * a session for icmp together.
	 * SA and policy ADD for TCP will be called 1st
	 * SA and Policy ADD for UDP will called 2nd
	 * SA and Policy ADD for ICMP will be called 3rd
	 */
	/*
	 * In the strongSwan ipsec kernel interface it makes
	 * all the SA add policy Add APIs part of a single object.
	 * So kernel will call all the APIs of that object together
	 */
	this->mutex->lock(this->mutex);
	if(id->dir == POLICY_IN)
	{
		ts_src = id->src_ts->get_from_address(id->src_ts);
		ts_dst = id->dst_ts->get_from_address(id->dst_ts);
		ts_src_outer = data->src->get_address(data->src);
		ts_dst_outer = data->dst->get_address(data->dst);
		memcpy(src, ts_src.ptr, ts_src.len);
		memcpy(dst, ts_dst.ptr, ts_src.len);
		memcpy(src_outer, ts_src_outer.ptr, ts_src_outer.len);
		memcpy(dst_outer, ts_dst_outer.ptr, ts_dst_outer.len);

		spi = ntohl(data->sa->esp.spi);
		offload_id = 0x00FFFFFF & spi;

		memset(mask, 0xFF, sizeof(uint32_t));
		id->dst_ts->to_subnet(id->dst_ts, &net_host, &netbits);
		memset(mac_mask, 0xFF, netbits/8);
		DBG2(DBG_KNL,"ADD in_policy offloadid=%d\n", offload_id);
		err = ipsec_rx_sa_classification_table(IPSEC_TABLE_ADD,
						       dst_outer, src_outer, spi, offload_id);
		if(err != IPSEC_SUCCESS)
			DBG2(DBG_KNL, "Inline_crypto_ipsec ipsec_rx_sa_classification_table:"
			     "add entry failed err_code[ %d]", err);

		if (data->sa->mode == MODE_TUNNEL) {
			err = ipsec_rx_post_decrypt_table(IPSEC_TABLE_ADD,
							  0, 0, 2 /*As of now SAD table programs req-id a 2 hence changing it to 2.
							  This can be changed to offload id once map ingress SPI to egress*/,
							  src_outer, dst_outer, offload_id);
			if(err == IPSEC_FAILURE) {
				DBG2(DBG_KNL, "Inline_crypto_ipsec ipsec_rx_post_decrypt_tabl:"
				     "add entry failed err_code[ %d]", err);
			} else if (err == IPSEC_DUP_ENTRY) {
				err = ipsec_rx_post_decrypt_table(IPSEC_TABLE_MOD,
								  0, 0, 2 /*As of now SAD table programs req-id a 2 hence changing it to 2.
								  This can be changed to offload id once map ingress SPI to egress*/,
								  src_outer, dst_outer, offload_id);
				if(err == IPSEC_FAILURE) {
					DBG2(DBG_KNL, "ipsec_rx_post_decrypt_table: modify entry failed");
				}
				if (!reqid_bitset(data->sa->reqid))
					DBG1(DBG_KNL, "ipsec_rx_post_decrypt_table: Failed to set the reqid bit!!");
			} else {
				DBG2(DBG_KNL, "ipsec_rx_post_decrypt_table: add entry done");
			}
			DBG2(DBG_KNL, "inbound tunnel mode table added offloadid=%d", offload_id);
		}

	} else if(id->dir == POLICY_OUT) {

		param_entry_t entry_key;
		ts_src = id->src_ts->get_from_address(id->src_ts);
		ts_dst = id->dst_ts->get_from_address(id->dst_ts);
		ts_src_outer = data->src->get_address(data->src);
		ts_dst_outer = data->dst->get_address(data->dst);

		memcpy(src, ts_src.ptr, ts_src.len);
		memcpy(dst, ts_dst.ptr, ts_src.len);
		memcpy(src_outer, ts_src_outer.ptr, ts_src_outer.len);
		memcpy(dst_outer, ts_dst_outer.ptr, ts_dst_outer.len);

		fill_entry_selector_policy(&entry_key.sel, id, data);
		current_entry = this->ipsec_offload_params->get(this->ipsec_offload_params,
								&entry_key);
		if (!current_entry) {
			DBG2(DBG_KNL,"[%s]: entry doesn't exist \n", __func__);
			return FAILED;
		}

		offload_id = current_entry->offload_id;
		DBG2(DBG_KNL,"ADD out_policy offloadid=%d\n", offload_id);

		memset(mask, 0xFF, sizeof(uint32_t));
		DBG2(DBG_KNL, "SPI [%x]", spi & 0x00FFFFFF);
                err = ipsec_spd_table(IPSEC_TABLE_ADD, dst, id->src_ts->get_protocol(id->src_ts), offload_id);
                if(err == IPSEC_FAILURE) {
                        DBG2(DBG_KNL, "Inline_crypto_ipsec ipsec_spd_table: add entry failed");
                } else if (err == IPSEC_DUP_ENTRY) {
                        err = ipsec_spd_table(IPSEC_TABLE_MOD, dst, id->src_ts->get_protocol(id->src_ts), offload_id);
                        if(err == IPSEC_FAILURE) {
                                DBG2(DBG_KNL, "Inline_crypto_ipsec ipsec_spd_table: modify entry failed");
                        }
                        if (!reqid_bitset(data->sa->reqid))
                                DBG1(DBG_KNL, " spd table: Failed to set the reqid bit!!");
                } else {
                        DBG2(DBG_KNL, "Inline_crypto_ipsec ipsec_spd_table: add entry done");
                }

		err = ipsec_tx_sa_classification_table(IPSEC_TABLE_ADD,
							   dst_outer, src_outer,
						       dst, src, 1,
						       offload_id, offload_id,
						       id->src_ts->get_protocol(id->src_ts),
						       data->sa->mode == MODE_TUNNEL, true);
		if(err == IPSEC_FAILURE) {
			DBG2(DBG_KNL, "Inline_crypto_ipsec ipsec_tx_sa_classification_table:"
			     "add entry failed for underlay");
		} else if (err == IPSEC_DUP_ENTRY) {
			err = ipsec_tx_sa_classification_table(IPSEC_TABLE_MOD,
								   dst_outer, src_outer,
							       dst, src, 1,
							       offload_id, offload_id,
							       id->src_ts->get_protocol(id->src_ts),
							       data->sa->mode == MODE_TUNNEL, true);
			if(err == IPSEC_FAILURE)
				DBG2(DBG_KNL, "Inline_crypto_ipsec ipsec_tx_sa_classification_table:"
				     "Modify entry failed for underlay");

			if (!reqid_bitset(data->sa->reqid))
				DBG1(DBG_KNL, "ipsec_tx_sa_classification_table: Failed to set the reqid bit!!");
		} else
			DBG2(DBG_KNL, "ipsec_tx_sa_classification_table add entry done for underlay");

                err = ipsec_tx_sa_classification_table(IPSEC_TABLE_ADD,
													   dst_outer, src_outer,
                                                       dst, src, 1,
                                                       offload_id, offload_id,
                                                       id->src_ts->get_protocol(id->src_ts),
                                                       data->sa->mode == MODE_TUNNEL, false);
                if(err == IPSEC_FAILURE) {
                        DBG2(DBG_KNL, "Inline_crypto_ipsec ipsec_tx_sa_classification_table:"
                             "add entry failed for non underlay");
                } else if (err == IPSEC_DUP_ENTRY) {
                        err = ipsec_tx_sa_classification_table(IPSEC_TABLE_MOD,
															   dst_outer, src_outer,
                                                               dst, src, 1,
                                                               offload_id, offload_id,
                                                               id->src_ts->get_protocol(id->src_ts),
                                                               data->sa->mode == MODE_TUNNEL, false);
                        if(err == IPSEC_FAILURE)
                                DBG2(DBG_KNL, "Inline_crypto_ipsec ipsec_tx_sa_classification_table:"
                                     "Modify entry failed for non underlay");

                        if (!reqid_bitset(data->sa->reqid))
                                DBG1(DBG_KNL, "ipsec_tx_sa_classification_table: Failed to set the reqid bit!!");
                } else
                        DBG2(DBG_KNL, "ipsec_tx_sa_classification_table add entry done for non underlay");

		if (data->sa->mode == MODE_TUNNEL) {
			err = ipsec_outer_ipv4_encap_mod_table(IPSEC_TABLE_ADD,
							       offload_id,
							       src_outer, dst_outer,
							       PROTO_IP, // proto should be 0x04 in tunnel mode for encap_mod_table
							       inner_smac, inner_dmac);
			if(err != IPSEC_SUCCESS)
				DBG2(DBG_KNL, "Inline_crypto_ipsec add_with_encap_outer_ipv4_mod:"
				     "add entry failed err_code[ %d]", err);
			// New table for combined recipe			
			err = ipsec_tunnel_id_table(IPSEC_TABLE_ADD,
							                    offload_id);
			if(err != IPSEC_SUCCESS)
				DBG2(DBG_KNL, "Inline_crypto_ipsec add_with_ipsec_tunnel_id_table:"
				     "add entry failed err_code[ %d]", err);
		}

		this->ipsec_offload_params->remove(this->ipsec_offload_params, current_entry);
	} else {
		DBG1(DBG_KNL, "Inline_crypto_ipsec doesn't support forward policies");
		this->mutex->unlock(this->mutex);
		return SUCCESS;
	}
	/* reqid is same across the rekey event, set reqid bit to identify rekey event*/

	this->mutex->unlock(this->mutex);
	free(current_entry);
	DBG2(DBG_KNL,"ADD Policy dir=%d offloadid=%d DONE\n", id->dir, offload_id);

	return SUCCESS;
}

METHOD(kernel_ipsec_t, query_policy, status_t,
	private_ipsec_offload_t *this, kernel_ipsec_policy_id_t *id,
	kernel_ipsec_query_policy_t *data, time_t *use_time)
{
	return SUCCESS;
}

METHOD(kernel_ipsec_t, del_policy, status_t,
	private_ipsec_offload_t *this, kernel_ipsec_policy_id_t *id,
	kernel_ipsec_manage_policy_t *data)
{
	chunk_t ts_src_outer = chunk_empty;
	chunk_t ts_dst_outer = chunk_empty;
	char src_outer[IPV6_LEN] = {0};
	char dst_outer[IPV6_LEN] = {0};
	chunk_t ts_src = chunk_empty;
	chunk_t ts_dst = chunk_empty;
	uint32_t spi, offload_id;
	char src[IPV6_LEN] = {0};
	char dst[IPV6_LEN] = {0};
	char mac_mask[16] = {0};
	host_t *net_host;
	uint8_t netbits;
	char mask[16];
	int err;

	char inner_smac[16] = {0x00, 0x02, 0x00, 0x00, 0x03, 0x18};
	char inner_dmac[16] = {0xb4, 0x96, 0x91, 0x9f, 0x67, 0x31};

	DBG2(DBG_KNL, "Del Policy dir=%d START", id->dir);

	if(id->dir == POLICY_IN)
	{
		ts_src = id->src_ts->get_from_address(id->src_ts);
		ts_dst = id->dst_ts->get_from_address(id->dst_ts);
		ts_src_outer = data->src->get_address(data->src);
		ts_dst_outer = data->dst->get_address(data->dst);
		memcpy(src, ts_src.ptr, ts_src.len);
		memcpy(dst, ts_dst.ptr, ts_src.len);
		memcpy(src_outer, ts_src_outer.ptr, ts_src_outer.len);
		memcpy(dst_outer, ts_dst_outer.ptr, ts_dst_outer.len);

		spi = ntohl(data->sa->esp.spi);
		offload_id = 0x00FFFFFF & spi;

		memset(mask, 0xFF, sizeof(uint32_t));
		id->dst_ts->to_subnet(id->dst_ts, &net_host, &netbits);
		memset(mac_mask, 0xFF, netbits/8);

		err = ipsec_rx_sa_classification_table(IPSEC_TABLE_DEL,
						       dst_outer, src_outer,
						       spi, offload_id);
		if(err != IPSEC_SUCCESS)
			DBG2(DBG_KNL, "Inline_crypto_ipsec ipsec_rx_sa_classification_table:"
			     "add entry failed err_code[ %d]", err);

		if (data->sa->mode == MODE_TUNNEL) {
			if (!reqid_bitget(data->sa->reqid)) {
				err = ipsec_rx_post_decrypt_table(IPSEC_TABLE_DEL,
								  0, 0, 2, src, dst,
								  offload_id);
				if(err != IPSEC_SUCCESS)
					DBG2(DBG_KNL, "Inline_crypto_ipsec ipsec_rx_post_decrypt_table:"
					"add entry failed err_code[ %d]", err);
			}
		}

		memset(mask, 0xFF, sizeof(uint32_t));

		if (!reqid_bitget(data->sa->reqid)) {
			err = ipsec_spd_table(IPSEC_TABLE_DEL, dst, id->src_ts->get_protocol(id->src_ts), offload_id);
                        if(err == IPSEC_FAILURE) {
                                DBG2(DBG_KNL, "Inline_crypto_ipsec ipsec_spd_table: del entry failed");
                        }
		}

		if (!reqid_bitget(data->sa->reqid)) {
			/* for Tx table dst = src in inbound */
			err = ipsec_tx_sa_classification_table(IPSEC_TABLE_DEL,
								   src_outer, dst_outer,
							       src, dst, 1,
							       offload_id, offload_id,
							       id->src_ts->get_protocol(id->src_ts),
							       data->sa->mode == MODE_TUNNEL, true);
			if(err == IPSEC_FAILURE)
				DBG2(DBG_KNL, "Inline_crypto_ipsec ipsec_tx_sa_classification_table:"
				     "del entry failed");

                        err = ipsec_tx_sa_classification_table(IPSEC_TABLE_DEL,
															   src_outer, dst_outer,
                                                               src, dst, 1,
                                                               offload_id, offload_id,
                                                               id->src_ts->get_protocol(id->src_ts),
                                                               data->sa->mode == MODE_TUNNEL, false);
                        if(err == IPSEC_FAILURE)
                                DBG2(DBG_KNL, "Inline_crypto_ipsec ipsec_tx_sa_classification_table:"
                                     "del entry failed");

		} else {
			reqid_bitclear(data->sa->reqid);
		}

		if (data->sa->mode == MODE_TUNNEL) {
			
			err = ipsec_outer_ipv4_encap_mod_table(IPSEC_TABLE_DEL,
							       offload_id, dst_outer, src_outer,
							       PROTO_IP, // proto should be 0x04 in tunnel mode for encap_mod_table
							       inner_smac, inner_dmac);
			if(err != IPSEC_SUCCESS)
				DBG2(DBG_KNL, "Inline_crypto_ipsec del_with_encap_outer_ipv4_mod:"
				     "del entry failed err_code[ %d]", err);
			//New table for combined recipe
			err = ipsec_tunnel_id_table(IPSEC_TABLE_DEL,
							       offload_id);
			if(err != IPSEC_SUCCESS)
				DBG2(DBG_KNL, "Inline_crypto_ipsec del_with_tunnel_id_table:"
				     "del entry failed err_code[ %d]", err);
		}

		/* Delete inbound and outbound SA */
		if (ipsec_sa_del(offload_id, 0) == IPSEC_SUCCESS)
			DBG1(DBG_KNL, "inbound SA Del for offload id=%d Success\n", offload_id);
		else
			DBG1(DBG_KNL, "inbound SA Del for offload id=%d Failed!!\n", offload_id);

		if (ipsec_sa_del(offload_id, 1) == IPSEC_SUCCESS)
			DBG1(DBG_KNL, "outbound SA Del offload id=%d Success\n", offload_id);
		else
			DBG1(DBG_KNL, "outbound SA Del offload id=%d Failed\n", offload_id);


	} else if(id->dir == POLICY_OUT) {
		DBG1(DBG_KNL, "Inline_crypto_ipsec: POLICY_OUT will be deleted as part of POLICY_IN");
		return SUCCESS;
	} else {
		DBG1(DBG_KNL, "Inline_crypto_ipsec doesn't support forward policies");
		return FAILED;
	}
	DBG2(DBG_KNL, "Del Policy dir=%d offloadid=%d DONE", id->dir, offload_id);

	return SUCCESS;
}

METHOD(kernel_ipsec_t, flush_policies, status_t,
	private_ipsec_offload_t *this)
{
	return SUCCESS;
}

METHOD(kernel_ipsec_t, bypass_socket, bool,
	private_ipsec_offload_t *this, int fd, int family)
{
	return SUCCESS;
}

METHOD(kernel_ipsec_t, enable_udp_decap, bool,
	private_ipsec_offload_t *this, int fd, int family, uint16_t port)
{
	return SUCCESS;
}

METHOD(kernel_ipsec_t, destroy, void,
	private_ipsec_offload_t *this)
{
	this->mutex->destroy(this->mutex);
	DBG2(DBG_KNL,"remove the hash table\n");
	this->ipsec_offload_params->destroy(this->ipsec_offload_params);
	this->close = true;
	usleep(TEN_MS);
	free(this);
}
/*
 * Described in header.
 */
ipsec_offload_t *ipsec_offload_create()
{
	private_ipsec_offload_t *this;

	INIT(this,
		.public = {
			.interface = {
				.get_features = _get_features,
				.get_spi = _get_spi,
				.get_cpi = _get_cpi,
				.add_sa  = _add_sa,
				.update_sa = _update_sa,
				.query_sa = _query_sa,
				.del_sa = _del_sa,
				.flush_sas = _flush_sas,
				.add_policy = _add_policy,
				.query_policy = _query_policy,
				.del_policy = _del_policy,
				.flush_policies = _flush_policies,
				.bypass_socket = _bypass_socket,
				.enable_udp_decap = _enable_udp_decap,
				.destroy = _destroy,
			},
		},
		.ipsec_listener = {
			.expire = expire,
		},
		/* This hash table maintains the offload id used for inbound and outbound SA and policy programming */
		.ipsec_offload_params = hashtable_create((hashtable_hash_t)param_hash,
							(hashtable_equals_t)param_equals, 32),
		.mutex = mutex_create(MUTEX_TYPE_DEFAULT),
	);
	if (gnmi_init() == IPSEC_FAILURE)
		DBG1(DBG_KNL, "gnmi init failed!\n");
	if (p4rt_init() == IPSEC_FAILURE)
		DBG1(DBG_KNL, "p4rt init failed!\n");

	this->close = false;
	ipsec_auto_config_init(&this->thread_id, &this->close);
//	ipsec->events->register_listener(ipsec->events, &this->ipsec_listener);
	DBG1(DBG_KNL, "p4rt and gnmi init Done \n");
	return &this->public;
};
