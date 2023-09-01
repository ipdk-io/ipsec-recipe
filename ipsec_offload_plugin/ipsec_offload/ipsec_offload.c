/******************************************************************
 ******************************************************************
 * Copyright (C) 2000-2002, 2004-2017, 2021-2022 Intel Corporation.
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
#include "ipsec_grpc_connect.h"

#define PROTO_BYTES_MAX 2000
#define CONFIG_DATA_MAX 1000

typedef struct private_ipsec_offload_t private_ipsec_offload_t;
#ifdef ENABLEGRPC
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
enum ipsec_status ipsec_tx_sa_classification_table(enum ipsec_table_op table_op,
						char dst_ip_addr[16],
						char src_ip_addr[16],
						char crypto_offload,
						uint32_t offloadid,
						uint32_t tunnel_id,
						uint8_t proto,
						bool tunnel_mode);
enum ipsec_status ipsec_rx_sa_classification_table(enum ipsec_table_op table_op,
						char dst_ip_addr[16],
						char src_ip_addr[16],
						uint32_t spi,
						uint32_t offloadid);
enum ipsec_status ipsec_rx_post_decrypt_table(enum ipsec_table_op table_op,
						char crypto_offload,
						char crypto_status,
						uint16_t crypt_tag,
						char dst_ip_addr[16],
						char dst_ip_mask[16],
						uint32_t match_priority);
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
#endif

#define SPI_MAX_LIMIT 0xffffff
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
	 * The below structure will be used to store egress ipsec params
	 */
	ipsec_offload_params_t out_ipsec_params;

	/**
	 * The below structure will be used to store ingress ipsec params
	 */
	ipsec_offload_params_t in_ipsec_params;
};


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
 * prepare the proto_bytes buffer for SA.
 */
static void get_proto_bytes(ipsec_offload_params_t *ipsec_params, char *proto_bytes)
{
	snprintf(proto_bytes, PROTO_BYTES_MAX-1, "offload_id:%d,\ndirection:%d,\nreq_id:%d,\n"
						"spi:%u,\next_seq_num:%d,\nanti_replay_window_size:%d,\n"
						"protocol_parameters:%d,\nmode:%d,\n"
						"esp_payload {\nencryption {\nencryption_algorithm:%d,\nkey:\"%s\",\nkey_len:%d,\n}\n},\n"
						"sa_hard_lifetime {\nbytes:%llu\n},\nsa_soft_lifetime {\nbytes: %llu\n}\n",
						ipsec_params->offloadid, ipsec_params->inbound, 2,
						ntohl(ipsec_params->spi), ipsec_params->esn, ipsec_params->replay_window,
						0, 0,
						ipsec_params->enc_alg, ipsec_params->key, ipsec_params->key_len,
						ipsec_params->lifetime.bytes.life, ipsec_params->lifetime.bytes.jitter);
}

static void fill_ipsec_policies(ipsec_offload_policy_t *policy,
				kernel_ipsec_policy_id_t *id,
				kernel_ipsec_manage_policy_t *data)
{
	chunk_t ts_src = chunk_empty;
	chunk_t ts_dst = chunk_empty;

	//Copy Destination TS
	ts_src = id->dst_ts->get_from_address(id->dst_ts);
	ts_dst = id->dst_ts->get_to_address(id->dst_ts);
	memcpy(&(policy->dst_ts.from),ts_src.ptr,ts_src.len);
	memcpy(&(policy->dst_ts.to),ts_dst.ptr,ts_dst.len);
	policy->dst_ts.from_port = id->dst_ts->get_from_port(id->dst_ts);
	policy->dst_ts.to_port = id->dst_ts->get_to_port(id->dst_ts);
	policy->dst_ts.type = id->dst_ts->get_type(id->dst_ts);
	policy->dst_ts.protocol = id->dst_ts->get_protocol(id->dst_ts);

	//Copy Source TS
	ts_src = chunk_empty;
	ts_dst = chunk_empty;
	ts_src = id->src_ts->get_from_address(id->src_ts);
	ts_dst = id->src_ts->get_to_address(id->src_ts);
	memcpy(&(policy->src_ts.from),ts_src.ptr,ts_src.len);
	memcpy(&(policy->src_ts.to),ts_dst.ptr,ts_dst.len);
	policy->src_ts.from_port = id->src_ts->get_from_port(id->src_ts);
	policy->src_ts.to_port = id->src_ts->get_to_port(id->src_ts);
	policy->src_ts.type = id->src_ts->get_type(id->src_ts);
	policy->src_ts.protocol = id->src_ts->get_protocol(id->src_ts);

	policy->dir= id->dir;
	policy->mode= data->sa->mode;
	policy->spi= data->sa->esp.spi;
}
static void fill_ipsec_params(ipsec_offload_params_t *params,
			kernel_ipsec_sa_id_t *id, kernel_ipsec_add_sa_t *data)
{
	params->replay_window = data->replay_window;
	/* ICE support AES GCM (0) and GMAC (1) mode, filling ipsec params accordingly
	 * TODO: need to move it to cypto_mgr
	 */
	if (data->enc_alg == 0x14)
		params->enc_alg = 0;
	else
		params->enc_alg = 1;

	params->spi = id->spi;
	params->offloadid = (0x00FFFFFF & ntohl(params->spi));
	params->proto = id->proto;
	params->esn = data->esn;
	params->inbound = data->inbound;
	params->key_len = data->enc_key.len;

	pack_key(data->enc_key.ptr, params->key, params->key_len);

	if(data->lifetime != NULL)
	{
		memcpy(&(params->lifetime), data->lifetime, sizeof(lifetime_cfg_t));
	}
}

static void fill_basic_params(ipsec_offload_basic_params_t *base,
			kernel_ipsec_sa_id_t *id) {

	/*Opcode We can't consider as for delete we don't know the inbound/outbound.
	 * One identifier will be use to decide a add/delete/read request.
	 * fill the address family info and send it to server*/
	chunk_t src = chunk_empty;
	chunk_t dst = chunk_empty;
	src = id->src->get_address(id->src);
	dst =  id->dst->get_address(id->dst);
	base->spi = id->spi;
	base->offloadid = (0x00FFFFFF & ntohl(base->spi));
	base->src.addr_family = id->src->get_family(id->src);
	base->dst.addr_family = id->dst->get_family(id->dst);
	base->src.addr_len = src.len;
	memcpy(base->src.addr, src.ptr, src.len);
	memcpy(base->dst.addr, dst.ptr, dst.len);
}

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
	int i;

	while (1) {
		if (*(bool *)arg == true) {
			pthread_exit(NULL);
		}

		int ret = ipsec_fetch_audit_log(config_data_buf, CONFIG_DATA_MAX);

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
	if (ipsec_subscribe_audit_log() == IPSEC_FAILURE) {
		DBG2(DBG_KNL,"Inline_crypto_ipsec audit log subscribe failed :: [%s] \n", __func__);
		return;
	}

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

uint32_t  gspi;
METHOD(kernel_ipsec_t, get_spi, status_t,
	private_ipsec_offload_t *this, host_t *src, host_t *dst,
	uint8_t protocol, uint32_t *spi)
{
	this->mutex->lock(this->mutex);
	uint32_t temp_spi;
	if (gspi == 0) {
	if(ipsec_set_pipe() == IPSEC_FAILURE)
	{
		DBG1(DBG_KNL, "Unable to set pipe\n");
//		return FAILED;
	}
	}
	if (ipsec_fetch_spi(spi) == IPSEC_FAILURE)
	{
		DBG1(DBG_KNL, "Unable to fetch spi from server\n");
		this->mutex->unlock(this->mutex);
		return FAILED;
	}
	temp_spi = *spi;
//#if 0	
	if (gspi == 0) {
		*spi = *spi & 0x00ffffff;
	  //     	*spi = *spi | 0x01000000;	// TEMP: make sa_index as 0
		gspi = 1;
	} else if (gspi == 1) {
		*spi = *spi & 0x00ffffff; //  
		*spi = *spi | 0x01000000; // TEMP: make sa_index as 0
	//	gspi = 0;
	}
//#endif
	*spi = temp_spi;	
	this->mutex->unlock(this->mutex);
	DBG2(DBG_KNL, "allocated SPI %.8x", ntohl(*spi));
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
	this->mutex->lock(this->mutex);
	ipsec_offload_params_t ipsec_sad_params;
	char proto_bytes[PROTO_BYTES_MAX] = {0};
	memset(&ipsec_sad_params,0x0,sizeof(ipsec_offload_params_t));
	/*According to MEV ICE HAS pages ICE supports AES GCM/GMAC 128/256 algos only.
	 * Adding a proper validation for these 2 algos. */

	if((data->enc_alg != 0x14) && (data->enc_alg != 0x15))
	{
		this->mutex->unlock(this->mutex);
		return FAILED;
	}
	if((data->enc_key.len != 20) && (data->enc_key.len != 36))
	{
		this->mutex->unlock(this->mutex);
		return FAILED;
	}

//	fill_basic_params(basic_params,id);
	fill_ipsec_params(&(ipsec_sad_params), id, data);
	/* New code for 2ports*/
	DBG1(DBG_KNL, "Going for SA add basic param offload ID %u dir =%d\n",ipsec_sad_params.offloadid,data->inbound);
	get_proto_bytes(&(ipsec_sad_params), proto_bytes);
	DBG2(DBG_KNL, "proto_bytes= %s", proto_bytes);
//	explicit_bzero(ipsec_params, sizeof(ipsec_offload_params_t));
	if (ipsec_sa_add(proto_bytes) == IPSEC_SUCCESS)
		DBG1(DBG_KNL, "SA Add Success in H/W offload-is %u direction %d \n",ipsec_sad_params.offloadid,ipsec_sad_params.inbound);
	else
		DBG1(DBG_KNL, "SA Add failed in H/W offload-id %u direction %d\n",ipsec_sad_params.offloadid,ipsec_sad_params.inbound);
	
	explicit_bzero(&(ipsec_sad_params),sizeof(ipsec_offload_params_t));
	explicit_bzero(proto_bytes, PROTO_BYTES_MAX);
	this->mutex->unlock(this->mutex);
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
	/*SAD Table Delete is covered in policy delete
	 * For MEV We need SA index and direction for deleting an entry.
	 * We can't derive the direction in this API
	 * Hence covering the SAD delete in del_policy
	 */
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
	int  err;
	char proto_bytes[PROTO_BYTES_MAX] = {0};
	char mask[16];
	char mac_mask[16];
	uint32_t spi;
	char inner_smac[16] = {0x00, 0x02, 0x00, 0x00, 0x03, 0x18};
	char inner_dmac[16] = {0xb4, 0x96, 0x91, 0x9f, 0x67, 0x31};
	chunk_t ts_src = chunk_empty;
	chunk_t ts_dst = chunk_empty;
	char from[IPV6_LEN] = {0};
	char to[IPV6_LEN] = {0};
	uint32_t temp_offloadid ;

	this->mutex->lock(this->mutex);
	if(id->dir == POLICY_IN)
	{
		//Copy Destination TS
		ts_src = id->src_ts->get_to_address(id->src_ts);
		ts_dst = id->dst_ts->get_to_address(id->dst_ts);
		memset(&(from),0x0,IPV6_LEN);
		memset(&(to),0x0,IPV6_LEN);
		memcpy(&(from),ts_src.ptr,ts_src.len);
		memcpy(&(to),ts_dst.ptr,ts_dst.len);
		DBG2(DBG_KNL," source %s len %d",ts_src.ptr,ts_src.len);
		DBG2(DBG_KNL," destination %s len %d",ts_dst.ptr,ts_dst.len);
		memset(mask, 0xFF, sizeof(uint32_t));
		memset(mac_mask, 0xFF, sizeof(mac_mask));
		DBG2(DBG_KNL," AAA inbound Policy Add ::saddr=%s daddr=%s spi=0x%x offloadid=0x%x \n",from,to, data->sa->esp.spi,(0x00FFFFFF & ntohl(data->sa->esp.spi)));
		DBG2(DBG_KNL,"to");
		for(int a=0;a<ts_dst.len;a++)
		{
			DBG2(DBG_KNL,"%x",to[a]);
		}
		DBG2(DBG_KNL,"from");
		for(int a=0;a<ts_dst.len;a++)
		{
			DBG2(DBG_KNL,"%x",from[a]);
		}
		DBG2(DBG_KNL,"RX data->sa->esp.spi=0x%x",data->sa->esp.spi);
		temp_offloadid = (0x00FFFFFF & ntohl(data->sa->esp.spi));
#ifdef CHANGE_BYTE_ORDER
		temp_offloadid = temp_offloadid <<16;
		DBG2(DBG_KNL,"setting temp_offloadid= %d",temp_offloadid);
#endif		
				
			 DBG2(DBG_KNL,"temp_offloadid= %d",temp_offloadid);
		err = ipsec_rx_sa_classification_table(IPSEC_TABLE_ADD,
						       to,
						       from,
						        ntohl(data->sa->esp.spi), /* need to ensure host endiannes*/
						        temp_offloadid/*(0x00FFFFFF & ntohl(data->sa->esp.spi))*//*spi & 0x00FFFFFF*/);
		if(err != IPSEC_SUCCESS)
			DBG2(DBG_KNL, "Inline_crypto_ipsec ipsec_rx_sa_classification_table: add entry failed err_code[ %d]", err);

		if (data->sa->mode == MODE_TUNNEL)
		{

			err = ipsec_outer_ipv4_decap_mod_table(
					IPSEC_TABLE_ADD,
					temp_offloadid,
					inner_smac,
					inner_dmac);
			if(err != IPSEC_SUCCESS)
				DBG2(DBG_KNL, "Inline_crypto_ipsec ipsec_outer_ipv4_decap_mod_table: add entry failed err_code[ %d]", err);
			err = ipsec_rx_post_decrypt_table(
					      IPSEC_TABLE_ADD,
					      1,
					      1,
					      temp_offloadid,
					      to,
					      mac_mask,
					      1);
			if(err != IPSEC_SUCCESS)
				DBG2(DBG_KNL, "Inline_crypto_ipsec iipsec_rx_post_decrypt_tabl: add entry failed err_code[ %d]", err);
		}

	}
	else if(id->dir == POLICY_OUT)
	{
		//Copy Destination TS
		ts_src = id->src_ts->get_from_address(id->dst_ts);
		ts_dst = id->dst_ts->get_from_address(id->src_ts);
		memset(&(from),0x0,IPV6_LEN);
		memset(&(to),0x0,IPV6_LEN);
		memcpy(&(from),ts_src.ptr,ts_src.len);
		memcpy(&(to),ts_dst.ptr,ts_dst.len);
		DBG2(DBG_KNL,"AAA outbound SA/Policy Add :: saddr=%s, daddr=%s, spi=0x%x, offloadid=0x%x protocol=%d\n",from,to,data->sa->esp.spi,(0x00FFFFFF & ntohl(data->sa->esp.spi)),id->src_ts->get_protocol(id->src_ts));
		DBG2(DBG_KNL,"to");
		for(int a=0;a<ts_dst.len;a++)
		{
			DBG2(DBG_KNL,"%x",to[a]);
		}
		DBG2(DBG_KNL,"to");
		for(int a=0;a<ts_dst.len;a++)
		{
			DBG2(DBG_KNL,"%x",from[a]);
		}

		memset(mask, 0xFF, sizeof(uint32_t));
		temp_offloadid = (0x00FFFFFF & ntohl(data->sa->esp.spi));
#ifdef CHANGE_BYTE_ORDER		
		temp_offloadid = temp_offloadid<<16;
		DBG2(DBG_KNL,"setting temp_offloadid= %d",temp_offloadid);
#endif		

			 DBG2(DBG_KNL,"temp_offloadid= 0x%x",temp_offloadid);
		err = ipsec_tx_spd_table(IPSEC_TABLE_ADD, from, mask, 1);
		if(err == IPSEC_FAILURE)
		{
			DBG2(DBG_KNL, "Inline_crypto_ipsec ipsec_tx_spd_table: add entry failed");
		}
		DBG2(DBG_KNL, "SPI [%x]", spi & 0x00FFFFFF);
		err = ipsec_tx_sa_classification_table(IPSEC_TABLE_ADD,
						       from,
						       to,
						       1,
						       temp_offloadid,/*(0x00FFFFFF & ntohl(data->sa->esp.spi)),i*//*spi & 0x00FFFFFF*/ /* need to ensure host endiannes*/
						       temp_offloadid,/*(0x00FFFFFF & ntohl(data->sa->esp.spi)),*//*spi & 0x00FFFFFF*/
						       id->src_ts->get_protocol(id->src_ts),
						       data->sa->mode == MODE_TUNNEL);
		if(err == IPSEC_FAILURE)
			DBG2(DBG_KNL, "Inline_crypto_ipsec ipsec_tx_sa_classification_table: add entry failed");

		if (data->sa->mode == MODE_TUNNEL)
		{
			err = ipsec_outer_ipv4_encap_mod_table(IPSEC_TABLE_ADD,
							       spi & 0x00FFFFFF,
							       from,
							       to,
							       id->src_ts->get_protocol(id->src_ts),
							       inner_smac, inner_dmac);
			if(err != IPSEC_SUCCESS)
				DBG2(DBG_KNL, "Inline_crypto_ipsec add_with_encap_outer_ipv4_mod: add entry failed err_code[ %d]", err);

		}
	}
	else
	{
		DBG1(DBG_KNL, "Inline_crypto_ipsec doesn't support forward policies");
		//return FAILED;
	}
	
	if(id->dir == POLICY_IN)
	DBG1(DBG_KNL, "AAA inbound policy add success returning SUCCESS");
	if(id->dir == POLICY_OUT)
	DBG1(DBG_KNL, "AAA outbound policy add success returning SUCCESS");
	this->mutex->unlock(this->mutex);
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
	int err;
	char mask[16];
	char mac_mask[16];
	uint32_t spi;
	char inner_smac[16] = {0x00, 0x02, 0x00, 0x00, 0x03, 0x18};
	char inner_dmac[16] = {0xb4, 0x96, 0x91, 0x9f, 0x67, 0x31};
	chunk_t ts_src = chunk_empty;
	chunk_t ts_dst = chunk_empty;
	char from[IPV6_LEN] = {0};
	char to[IPV6_LEN] = {0};
	uint32_t temp_offloadid ;

	DBG2(DBG_KNL, "Del Policy API called with dir=%d", id->dir);

	this->mutex->lock(this->mutex);
	if(id->dir == POLICY_IN)
	{
		//Copy Destination TS
		ts_src = id->src_ts->get_to_address(id->src_ts);
		ts_dst = id->dst_ts->get_to_address(id->dst_ts);
		memset(&(from),0x0,IPV6_LEN);
		memset(&(to),0x0,IPV6_LEN);
		memcpy(&(from),ts_src.ptr,ts_src.len);
		memcpy(&(to),ts_dst.ptr,ts_dst.len);
		memset(mask, 0xFF, sizeof(uint32_t));
		memset(mac_mask, 0xFF, sizeof(mac_mask));
		DBG2(DBG_KNL," source %s len %d",ts_src.ptr,ts_src.len);
		DBG2(DBG_KNL," destination %s len %d",ts_dst.ptr,ts_dst.len);
		temp_offloadid = (0x00FFFFFF & ntohl(data->sa->esp.spi));
		DBG2(DBG_KNL,"to");
		for(int a=0;a<ts_dst.len;a++)
		{
			DBG2(DBG_KNL,"%x",to[a]);
		}
		DBG2(DBG_KNL,"from");
		for(int a=0;a<ts_dst.len;a++)
		{
			DBG2(DBG_KNL,"%x",from[a]);
		}
#ifdef CHANGE_BYTE_ORDER
		temp_offloadid = temp_offloadid <<16;
		DBG2(DBG_KNL,"setting temp_offloadid= %d",temp_offloadid);
#endif		

			 DBG2(DBG_KNL,"temp_offloadid= %d",temp_offloadid);
		err = ipsec_rx_sa_classification_table(IPSEC_TABLE_DEL,
						       to,
						       from,
						        ntohl(data->sa->esp.spi), /* need to ensure host endiannes*/
						        temp_offloadid/*(0x00FFFFFF & ntohl(data->sa->esp.spi))*//*spi & 0x00FFFFFF*/);
		if(err != IPSEC_SUCCESS)
			DBG2(DBG_KNL, "Inline_crypto_ipsec ipsec_rx_sa_classification_table: delete entry failed err_code[ %d]", err);

		if (data->sa->mode == MODE_TUNNEL)
		{
			err = ipsec_outer_ipv4_decap_mod_table(IPSEC_TABLE_DEL, temp_offloadid, inner_smac, inner_dmac);
			if(err != IPSEC_SUCCESS)
				DBG2(DBG_KNL, "Inline_crypto_ipsec ipsec_outer_ipv4_decap_mod_table: delete entry failed err_code[ %d]", err);
			err = ipsec_rx_post_decrypt_table( IPSEC_TABLE_DEL, 1, 1, temp_offloadid, to, mac_mask, 1);
			if(err != IPSEC_SUCCESS)
				DBG2(DBG_KNL, "Inline_crypto_ipsec iipsec_rx_post_decrypt_tabl: delete entry failed err_code[ %d]", err);
		}
		if (ipsec_sa_del(temp_offloadid,  id->dir) != IPSEC_SUCCESS)
		{
			DBG1(DBG_KNL, " Inbound SA Del Failed index %u dir %d\n", temp_offloadid, id->dir);
		}	
	}
  else if(id->dir == POLICY_OUT)
	{
		//Copy Destination TS
		ts_src = id->src_ts->get_from_address(id->dst_ts);
		ts_dst = id->dst_ts->get_from_address(id->src_ts);
		memset(&(from),0x0,IPV6_LEN);
		memset(&(to),0x0,IPV6_LEN);
		memcpy(&(from),ts_src.ptr,ts_src.len);
		memcpy(&(to),ts_dst.ptr,ts_dst.len);
		DBG2(DBG_KNL,"AAA outbound SA/Policy Add :: saddr=%s, daddr=%s, spi=0x%x, offloadid=0x%x protocol=%d\n",from,to,data->sa->esp.spi,(0x00FFFFFF & ntohl(data->sa->esp.spi)),id->src_ts->get_protocol(id->src_ts));
		DBG2(DBG_KNL,"destination");

		memset(mask, 0xFF, sizeof(uint32_t));
		temp_offloadid = (0x00FFFFFF & ntohl(data->sa->esp.spi));
#ifdef CHANGE_BYTE_ORDER
		temp_offloadid = temp_offloadid<<16;
		DBG2(DBG_KNL,"setting temp_offloadid= %d",temp_offloadid);
#endif		
			

			 DBG2(DBG_KNL,"to");
			 for(int a=0;a<ts_dst.len;a++)
			 {
				 DBG2(DBG_KNL,"%x",to[a]);
			 }
			 DBG2(DBG_KNL,"from");
			 for(int a=0;a<ts_dst.len;a++)
			 {
				 DBG2(DBG_KNL,"%x",from[a]);
			 }
			 DBG2(DBG_KNL,"temp_offloadid= 0x%x",temp_offloadid);
		err = ipsec_tx_spd_table(IPSEC_TABLE_DEL, from, mask, 1);
		if(err == IPSEC_FAILURE)
		{
			DBG2(DBG_KNL, "Inline_crypto_ipsec ipsec_tx_spd_table: del entry failed");
		}
		DBG2(DBG_KNL, "SPI [%x]", spi & 0x00FFFFFF);
		err = ipsec_tx_sa_classification_table(IPSEC_TABLE_DEL,
						       from,
						       to,
						       1,
						       temp_offloadid,/*(0x00FFFFFF & ntohl(data->sa->esp.spi)),i*//*spi & 0x00FFFFFF*/ /* need to ensure host endiannes*/
						       temp_offloadid,/*(0x00FFFFFF & ntohl(data->sa->esp.spi)),*//*spi & 0x00FFFFFF*/
						       id->src_ts->get_protocol(id->src_ts),
						       data->sa->mode == MODE_TUNNEL);
		if(err == IPSEC_FAILURE)
			DBG2(DBG_KNL, "Inline_crypto_ipsec ipsec_tx_sa_classification_table: delete entry failed");
		if (data->sa->mode == MODE_TUNNEL)
		{
			err = ipsec_outer_ipv4_encap_mod_table(IPSEC_TABLE_DEL,
							       spi & 0x00FFFFFF,
							       from,
							       to,
							       id->src_ts->get_protocol(id->src_ts),
							       inner_smac, inner_dmac);
			if(err != IPSEC_SUCCESS)
				DBG2(DBG_KNL, "Inline_crypto_ipsec add_with_encap_outer_ipv4_mod: delete entry failed err_code[ %d]", err);

		}
		if (ipsec_sa_del(temp_offloadid,  id->dir) != IPSEC_SUCCESS)
		{
			DBG1(DBG_KNL, " Outbound SA Del Failed index %u dir %d\n", temp_offloadid, id->dir);
		}	
	}
	else
	{
		this->mutex->unlock(this->mutex);
		DBG1(DBG_KNL, "Inline_crypto_ipsec doesn't support forward policies");
		return FAILED;
	}

	this->mutex->unlock(this->mutex);
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
#ifndef ENABLEGRPC
	close(this->socket);
#endif
	this->mutex->destroy(this->mutex);
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
	int sock =-1;

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
		.mutex = mutex_create(MUTEX_TYPE_DEFAULT),
	);
#ifndef ENABLEGRPC
	ipsec_sa_get_sock(&sock);
#else
	if (gnmi_init() == IPSEC_FAILURE)
		DBG1(DBG_KNL, "gnmi init failed!\n");
	if (p4rt_init() == IPSEC_FAILURE)
		DBG1(DBG_KNL, "p4rt init failed!\n");

	this->close = false;
	ipsec_auto_config_init(&this->thread_id, &this->close);
#endif
	this->socket = sock;
//	ipsec->events->register_listener(ipsec->events, &this->ipsec_listener);
	return &this->public;
};
