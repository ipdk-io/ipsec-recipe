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

#include <memory>
#include <string>
#include <sstream>
#include <fstream>
#include <iostream>
#include <chrono>
#include <thread>
#include <fcntl.h>
#include <unistd.h>
#include <iomanip>
#include <grpcpp/grpcpp.h>
#include "p4runtime.grpc.pb.h"
#include "ipsec_grpc_connect.h"
#include <google/protobuf/text_format.h>
#include <google/protobuf/io/zero_copy_stream.h>
#include <google/protobuf/io/zero_copy_stream_impl.h>
#include <arpa/inet.h>

using grpc::ClientContext;
using grpc::Status;

using p4::v1::P4Runtime;
using p4::v1::WriteRequest;
using p4::v1::WriteResponse;
using p4::v1::TableEntry;

using std::nothrow;
using std::string;
using std::ifstream;
using std::ostringstream;
using std::to_string;

extern "C" enum ipsec_status ipsec_tx_spd_table(enum ipsec_table_op table_op,
						char dst_ip_addr[16],
						char  mask[16],
						uint32_t match_priority);
extern "C" enum ipsec_status ipsec_tx_sa_classification_table(
						enum ipsec_table_op table_op,
						char dst_ip_addr[16],
						char src_ip_addr[16],
						char crypto_offload,
						uint32_t offloadid,
						uint32_t tunnel_id,
						uint8_t proto,
						bool tunnel_mode);
extern "C" enum ipsec_status ipsec_rx_sa_classification_table(
						enum ipsec_table_op table_op,
						char dst_ip_addr[16],
						char src_ip_addr[16],
						uint32_t spi,
						uint32_t offloadid);
extern "C" enum ipsec_status ipsec_rx_post_decrypt_table(
						      enum ipsec_table_op table_op,
						      char crypto_offload,
						      char crypto_status,
						      uint16_t crypt_tag,
						      char dst_ip_addr[16],
						      char dst_ip_mask[16],
						      uint32_t match_priority);
extern "C" enum ipsec_status ipsec_outer_ipv4_encap_mod_table(
						enum ipsec_table_op table_op,
						uint32_t mod_blob_ptr,
						char src_ip_addr[16],
						char dst_ip_addr[16],
						uint32_t proto,
						char smac[16],
						char dmac[16]);
extern "C" enum ipsec_status ipsec_outer_ipv4_decap_mod_table(
						enum ipsec_table_op table_op,
						uint32_t mod_blob_ptr,
						char inner_smac[16],
						char inner_dmac[16]);

extern "C" enum ipsec_status ipsec_set_pipe(void);

#define P4_INFO_FILE "/var/tmp/linux_networking.p4info.txt"
#define P4_BIN_FILE "/var/tmp/ipsec_fixed_func.pb.bin"
#define DEVICE_ID        1
#define ELECTION_ID_HIGH 1
#define ELECTION_ID_LOW  0

#define IPSEC_TX_SPD_TBLE_ID 		44556728
#define IPSEC_PROTECT_ACTION_ID		21435079
#define TX_SA_CLASSIFICATION_TABLE_ID	46182446
#define RX_SA_CLASSIFICATION_TABLE_ID	45068641
#define IPSEC_TX_TUNNEL_ACTION_ID	28450616
#define IPSEC_TX_TRANSPORT_ID 		17156783
#define IPSEC_TX_TUNNEL_ID 		28450616
#define IPSEC_RX_TUNNEL_ACTION_ID	33177492
#define OUTER_IPV4_ENCAP_MOD_TABLE_ID	41572460
#define ENCAP_OUTER_IPV4_MOD_ACTION_ID	26814003
#define OUTER_IPV4_DECAP_MOD_TABLE_ID   36144080
#define DECAP_OUTER_IPV4_MOD_ACTION_ID  19827329
#define RX_POST_DECRYPT_TABLE_ID	41233864
#define RX_POST_DECRYPT_ACTION_ID	16818337
string rt_address = "localhost:53000";

/* This is temporary workaround Need to find proper solution */
#define STREAM_CHANNEL() \
			p4::v1::StreamMessageRequest req_stream; \
			p4::v1::StreamMessageResponse resp_stream;\
			ClientContext context_stream;\
			stream_channel = stub_->StreamChannel(&context_stream);\
			auto arbitration = req_stream.mutable_arbitration();\
			arbitration->set_device_id(DEVICE_ID);\
			arbitration->mutable_election_id()->set_high(ELECTION_ID_HIGH);\
			arbitration->mutable_election_id()->set_low(ELECTION_ID_LOW);\
			if(!stream_channel->Write(req_stream))\
				std::cout << "Unable to initiate P4RT connection";\
			if (!stream_channel->Read(&resp_stream))\
				std::cout << "P4RT stream closed while awaiting arbitration response";\
			if (resp_stream.update_case() != ::p4::v1::StreamMessageResponse::kArbitration)\
				std::cout << "No arbitration update received";\
			std::cout << "Is master:"<< resp_stream.arbitration().status().code()<< "\n";\
			if (resp_stream.arbitration().device_id() != DEVICE_ID)\
				std::cout << "device id mismatch"<< resp_stream.arbitration().device_id()<< "\n";\

class IPSecP4RuntimeClient {
	public:
		IPSecP4RuntimeClient(const std::string& server)
		{
		    stub_ = P4Runtime::NewStub(grpc::CreateChannel(
						server,
						grpc::InsecureChannelCredentials()));
		}

		void SetPipe (void) {
			::p4::v1::SetForwardingPipelineConfigRequest req;
			::p4::v1::SetForwardingPipelineConfigResponse resp;
			ClientContext context;
			string p4bin_str;
			string p4info_file = P4_INFO_FILE;
			std::ifstream ip4info_file;
			std::string text;
			string p4bin_file = P4_BIN_FILE;
			std::ifstream ip4bin_file;
			std::string* buffer;

			STREAM_CHANNEL();
			req.set_device_id(DEVICE_ID);
			req.mutable_election_id()->set_high(ELECTION_ID_HIGH);
			req.mutable_election_id()->set_low(ELECTION_ID_LOW);
			req.set_action(
				p4::v1::SetForwardingPipelineConfigRequest::VERIFY_AND_COMMIT);

			/* Read p4 info */
			ip4info_file.open(p4info_file.c_str());
			if (!ip4info_file.is_open()) {
				std::cout <<"failed to open " << p4info_file.c_str();
				return;
			}

			std::string contents_p4info(
					(std::istreambuf_iterator<char>(ip4info_file)),
					(std::istreambuf_iterator<char>()));
			text.append(contents_p4info);

			if (!::google::protobuf::TextFormat::ParseFromString(
						text,req.mutable_config()->mutable_p4info())) {
			       std::cout <<"failed to parse";
				return;
			}

			ip4info_file.close();

			/* Read p4 bin */
			ip4bin_file.open(p4bin_file.c_str());
			if (!ip4bin_file.is_open()) {
				std::cout <<"failed to open " << p4bin_file.c_str();
				return;
			}

			buffer = req.mutable_config()->mutable_p4_device_config();

			std::string contents_p4bin((std::istreambuf_iterator<char>(ip4bin_file)),
					(std::istreambuf_iterator<char>()));

			buffer->append(contents_p4bin);
			ip4bin_file.close();

			Status status = stub_->SetForwardingPipelineConfig(&context, req, &resp);
			std::cout << status.error_code() << ": " << status.error_message()
				<< std::endl;
		}

		enum ipsec_status GetPipe (void) {
			::p4::v1::GetForwardingPipelineConfigRequest req;
			::p4::v1::GetForwardingPipelineConfigResponse resp;
			ClientContext context;

			STREAM_CHANNEL();
			req.set_device_id(DEVICE_ID);
			req.set_response_type(::p4::v1::GetForwardingPipelineConfigRequest::ALL);

			Status status = stub_->GetForwardingPipelineConfig(&context, req, &resp);
			if(status.ok()) {
                                return IPSEC_SUCCESS;
                        } else {
                                std::cout << status.error_code() << ": " << status.error_message()
                                        << std::endl;
                                return IPSEC_FAILURE;
                        }
		}

		string convert_ip_to_str (char src_str[]) {
			string 		tmpstr;
			ostringstream 	str1;

			str1 << src_str[0] << src_str[1] << src_str[2] << src_str[3];
			tmpstr = str1.str();
			return tmpstr;
		}

		string ConvertMacToStr (const char mac[6]) {
			string 		tmpstr;
			ostringstream 	str1;

			str1 << mac[0] << mac[1] << mac[2] << mac[3] << mac[4] << mac[5];
			tmpstr = str1.str();
			return tmpstr;

		}
		string Uint32ToByteStream(uint32_t val) {
			uint32_t tmp = htonl(val);
			std::string bytes = "";
			bytes.assign(reinterpret_cast<char*>(&tmp), sizeof(uint32_t));
			//Strip leading zeroes.
			while (bytes.size() > 1 && bytes[0] == '\x00') {
				bytes = bytes.substr(1);
			}
			return bytes;
		}

		enum ipsec_status P4runtimeIpsecTxSpdTable(enum ipsec_table_op table_op,
							char dst_ip_addr[16],
							char mask[16],
							uint32_t match_priority) {
			TableEntry table_entry;
			WriteRequest request;
			p4::v1::FieldMatch *field_match;
			p4::v1::Update *update = request.add_updates();
			WriteResponse reply;
			ClientContext context;
			p4::v1::FieldMatch_Ternary *ternary;

			STREAM_CHANNEL();

			table_entry.set_table_id(IPSEC_TX_SPD_TBLE_ID);
			table_entry.set_priority(match_priority);

			field_match=table_entry.add_match();
			field_match->set_field_id(1);
			ternary = field_match->mutable_ternary();

			ternary->set_value(convert_ip_to_str(dst_ip_addr));
			ternary->set_mask(convert_ip_to_str(mask));

#if 0
			field_match=table_entry.add_match();
			field_match->set_field_id(2);
			ternary->set_value(prio);
#endif
			if (table_op == IPSEC_TABLE_ADD) {
				table_entry.mutable_action()->mutable_action()->set_action_id(IPSEC_PROTECT_ACTION_ID);
				update->set_type(p4::v1::Update::INSERT);
			} else {

				update->set_type(p4::v1::Update::DELETE);
			}


			update->mutable_entity()->mutable_table_entry()->CopyFrom(table_entry);

			request.set_device_id(DEVICE_ID);
			request.mutable_election_id()->set_high(ELECTION_ID_HIGH);
			request.mutable_election_id()->set_low(ELECTION_ID_LOW);

			Status status = stub_->Write(&context, request, &reply);
			if(status.ok()) {
				return IPSEC_SUCCESS;
			} else {
				std::cout << status.error_code() << ": " << status.error_message()
					<< std::endl;
				return IPSEC_FAILURE;
			}
		}

		enum ipsec_status P4runtimeIpsecTxSaClassificationTable(enum ipsec_table_op table_op,
									char dst_ip_addr[16],
									char src_ip_addr[16],
									char crypto_offload,
									uint32_t offloadid,
									uint32_t tunnel_id,
									uint8_t proto,
									bool tunnel_mode) {
			TableEntry table_entry;
			WriteRequest request;
			p4::v1::FieldMatch *field_match;
			p4::v1::Update *update = request.add_updates();
			WriteResponse reply;
			ClientContext context;
			p4::v1::Action_Param *params;
	  		std::string protocol={6};
	  		std::string offload = {1};
			table_entry.set_table_id(TX_SA_CLASSIFICATION_TABLE_ID);

			STREAM_CHANNEL();
			//offload = to_string((uint32_t)crypto_offload);
			field_match = table_entry.add_match();
			field_match->set_field_id(1);
			field_match->mutable_exact()->set_value(offload);

			field_match = table_entry.add_match();
			field_match->set_field_id(2);
			field_match->mutable_exact()->set_value(convert_ip_to_str(src_ip_addr));

			field_match=table_entry.add_match();
			field_match->set_field_id(3);
			field_match->mutable_exact()->set_value(convert_ip_to_str(dst_ip_addr));

			field_match = table_entry.add_match();
			field_match->set_field_id(4);

			/* Nee to root cause and fix properly */
			protocol[0] = 6;
			field_match->mutable_exact()->set_value(protocol);

			if (table_op == IPSEC_TABLE_ADD) {
				if (tunnel_mode)
					table_entry.mutable_action()->mutable_action()->set_action_id(IPSEC_TX_TUNNEL_ID);
				else
					table_entry.mutable_action()->mutable_action()->set_action_id(IPSEC_TX_TRANSPORT_ID);
				params = table_entry.mutable_action()->mutable_action()->add_params();
				params->set_param_id(1);
				params->set_value(Uint32ToByteStream(offloadid));

				if (tunnel_mode) {
					params = table_entry.mutable_action()->mutable_action()->add_params();
					params->set_param_id(2);
					params->set_value(Uint32ToByteStream(tunnel_id));
				}
				update->set_type(p4::v1::Update::INSERT);
			} else {
				update->set_type(p4::v1::Update::DELETE);
			}

			update->mutable_entity()->mutable_table_entry()->CopyFrom(table_entry);

			request.set_device_id(DEVICE_ID);
			request.mutable_election_id()->set_high(ELECTION_ID_HIGH);
			request.mutable_election_id()->set_low(ELECTION_ID_LOW);

			Status status = stub_->Write(&context, request, &reply);
			if(status.ok()) {
				return IPSEC_SUCCESS;
			} else {
				std::cout << status.error_code() << ": " << status.error_message()
					<< std::endl;
				return IPSEC_FAILURE;
			}
		}

		enum ipsec_status P4runtimeIpsecRxSaClassificationTable(enum ipsec_table_op table_op,
									char dst_ip_addr[16],
									char src_ip_addr[16],
									uint32_t spi,
									uint32_t sa_idx) {
			TableEntry table_entry;
			WriteRequest request;
			p4::v1::FieldMatch *field_match;
			p4::v1::Update *update = request.add_updates();
			WriteResponse reply;
			ClientContext context;
			p4::v1::Action_Param *params;

			STREAM_CHANNEL();
			table_entry.set_table_id(RX_SA_CLASSIFICATION_TABLE_ID);

			field_match = table_entry.add_match();
			field_match->set_field_id(1);
			field_match->mutable_exact()->set_value(convert_ip_to_str(src_ip_addr));

			field_match = table_entry.add_match();
			field_match->set_field_id(2);
			field_match->mutable_exact()->set_value(convert_ip_to_str(dst_ip_addr));

			field_match = table_entry.add_match();
			field_match->set_field_id(3);
			field_match->mutable_exact()->set_value(Uint32ToByteStream(spi));
			std::cout <<spi << "\n";
			std::cout << to_string(spi) <<"\n";
			std::cout << Uint32ToByteStream(spi) <<"\n";

			if (table_op == IPSEC_TABLE_ADD) {
				table_entry.mutable_action()->mutable_action()->set_action_id(IPSEC_RX_TUNNEL_ACTION_ID);
				params = table_entry.mutable_action()->mutable_action()->add_params();
				params->set_param_id(1);
				params->set_value(Uint32ToByteStream(sa_idx));

				update->set_type(p4::v1::Update::INSERT);
			} else {
				update->set_type(p4::v1::Update::DELETE);
			}

			update->mutable_entity()->mutable_table_entry()->CopyFrom(table_entry);

			request.set_device_id(DEVICE_ID);
			request.mutable_election_id()->set_high(ELECTION_ID_HIGH);
			request.mutable_election_id()->set_low(ELECTION_ID_LOW);

			Status status = stub_->Write(&context, request, &reply);
			if(status.ok()) {
				return IPSEC_SUCCESS;
			} else {
				std::cout << status.error_code() << ": " << status.error_message()
					<< std::endl;
				return IPSEC_FAILURE;
			}
		}

		enum ipsec_status P4runtimeIpsecRxPostDecryptTable(enum ipsec_table_op table_op,
								   char crypto_offload,
								   char crypto_status,
								   uint16_t crypto_tag,
								   char dst_ip_addr[16],
								   char dst_ip_mask[16],
								   uint32_t match_priority) {
			TableEntry table_entry;
			WriteRequest request;
			p4::v1::FieldMatch *field_match;
			p4::v1::Update *update = request.add_updates();
			WriteResponse reply;
			ClientContext context;
			p4::v1::Action_Param *params;
			p4::v1::FieldMatch_Ternary *ternary;

			STREAM_CHANNEL();
	  		std::string offload = {0};
	  		std::string offload_mask = {1};
	  		std::string crypt_status = {0};
	  		std::string crypt_status_mask = {1};
	  		char crypt_tag_mask[4];
	  		std::string inner_next_hop_id = {1};
			memset(crypt_tag_mask, 0xff, sizeof(crypt_tag_mask));

			table_entry.set_table_id(RX_POST_DECRYPT_TABLE_ID);
			table_entry.set_priority(match_priority);

			field_match = table_entry.add_match();
			field_match->set_field_id(1);
			ternary = field_match->mutable_ternary();
			ternary->set_value(crypt_status);
			ternary->set_mask(crypt_status_mask);

			field_match = table_entry.add_match();
			field_match->set_field_id(2);
			ternary = field_match->mutable_ternary();
			ternary->set_value(offload);
			ternary->set_mask(offload_mask);

			field_match = table_entry.add_match();
			field_match->set_field_id(3);
			ternary = field_match->mutable_ternary();
			ternary->set_value(Uint32ToByteStream(crypto_tag));
			ternary->set_mask(convert_ip_to_str(crypt_tag_mask));

			field_match = table_entry.add_match();
			field_match->set_field_id(4);
			ternary = field_match->mutable_ternary();
			ternary->set_value(convert_ip_to_str(dst_ip_addr));
			ternary->set_mask(convert_ip_to_str(dst_ip_mask));

			if (table_op == IPSEC_TABLE_ADD) {
				table_entry.mutable_action()->mutable_action()->set_action_id(RX_POST_DECRYPT_ACTION_ID);
				params = table_entry.mutable_action()->mutable_action()->add_params();
				params->set_param_id(1);
				params->set_value(inner_next_hop_id);

				update->set_type(p4::v1::Update::INSERT);
			} else {

				update->set_type(p4::v1::Update::DELETE);
			}
			update->mutable_entity()->mutable_table_entry()->CopyFrom(table_entry);

			request.set_device_id(DEVICE_ID);
			request.mutable_election_id()->set_high(ELECTION_ID_HIGH);
			request.mutable_election_id()->set_low(ELECTION_ID_LOW);

			Status status = stub_->Write(&context, request, &reply);
			if(status.ok()) {
				return IPSEC_SUCCESS;
			} else {
				std::cout << status.error_code() << ": " << status.error_message()
					<< std::endl;
				return IPSEC_FAILURE;
			}
		}


		enum ipsec_status P4runtimeIpsecOuterIpv4EncapModTable(enum ipsec_table_op table_op,
								       uint32_t mod_blob_ptr,
								       char src_ip_addr[16],
								       char dst_ip_addr[16],
								       uint32_t proto,
								       char smac[16],
								       char dmac[16]) {
			TableEntry table_entry;
			WriteRequest request;
			p4::v1::FieldMatch *field_match=table_entry.add_match();
			p4::v1::Update *update = request.add_updates();
			WriteResponse reply;
			ClientContext context;
			p4::v1::Action_Param *params;
	  		std::string protocol={6};
	  		std::string offload = {1};

			STREAM_CHANNEL();
			table_entry.set_table_id(OUTER_IPV4_ENCAP_MOD_TABLE_ID);

			field_match->set_field_id(1);
			field_match->mutable_exact()->set_value((char*)&mod_blob_ptr);

			if (table_op == IPSEC_TABLE_ADD) {
				table_entry.mutable_action()->mutable_action()->set_action_id(ENCAP_OUTER_IPV4_MOD_ACTION_ID);
				params = table_entry.mutable_action()->mutable_action()->add_params();
				params->set_param_id(1);
				params->set_value(convert_ip_to_str(src_ip_addr));

				params = table_entry.mutable_action()->mutable_action()->add_params();
				params->set_param_id(2);
				params->set_value(convert_ip_to_str(dst_ip_addr));

				params = table_entry.mutable_action()->mutable_action()->add_params();
				params->set_param_id(3);
				params->set_value(protocol);

				params = table_entry.mutable_action()->mutable_action()->add_params();
				params->set_param_id(4);
				params->set_value(ConvertMacToStr(smac));

				params = table_entry.mutable_action()->mutable_action()->add_params();
				params->set_param_id(5);
				params->set_value(ConvertMacToStr(dmac));

				update->set_type(p4::v1::Update::INSERT);
			} else {
				update->set_type(p4::v1::Update::DELETE);
			}
			update->mutable_entity()->mutable_table_entry()->CopyFrom(table_entry);

			request.set_device_id(DEVICE_ID);
			request.mutable_election_id()->set_high(ELECTION_ID_HIGH);
			request.mutable_election_id()->set_low(ELECTION_ID_LOW);

			Status status = stub_->Write(&context, request, &reply);
			if(status.ok()) {
				return IPSEC_SUCCESS;
			} else {
				std::cout << status.error_code() << ": " << status.error_message()
					<< std::endl;
				return IPSEC_FAILURE;
			}
		}

		enum ipsec_status P4runtimeIpsecOuterIpv4DecapModTable(enum ipsec_table_op table_op,
								       uint32_t mod_blob_ptr,
								       char inner_smac[16],
								       char inner_dmac[16]) {
			TableEntry table_entry;
			WriteRequest request;
			p4::v1::FieldMatch *field_match=table_entry.add_match();
			p4::v1::Update *update = request.add_updates();
			WriteResponse reply;
			ClientContext context;
			p4::v1::Action_Param *params;

			STREAM_CHANNEL();
			table_entry.set_table_id(OUTER_IPV4_DECAP_MOD_TABLE_ID);

			field_match->set_field_id(1);
			field_match->mutable_exact()->set_value(Uint32ToByteStream(mod_blob_ptr));

			if (table_op == IPSEC_TABLE_ADD) {
				table_entry.mutable_action()->mutable_action()->set_action_id(DECAP_OUTER_IPV4_MOD_ACTION_ID);
				params = table_entry.mutable_action()->mutable_action()->add_params();
				params->set_param_id(1);
				params->set_value(ConvertMacToStr(inner_dmac));

				params = table_entry.mutable_action()->mutable_action()->add_params();
				params->set_param_id(2);
				params->set_value(ConvertMacToStr(inner_smac));

				update->set_type(p4::v1::Update::INSERT);
			} else {
				update->set_type(p4::v1::Update::DELETE);
			}

			update->mutable_entity()->mutable_table_entry()->CopyFrom(table_entry);

			request.set_device_id(DEVICE_ID);
			request.mutable_election_id()->set_high(ELECTION_ID_HIGH);
			request.mutable_election_id()->set_low(ELECTION_ID_LOW);

			Status status = stub_->Write(&context, request, &reply);
			if(status.ok()) {
				return IPSEC_SUCCESS;
			} else {
				std::cout << status.error_code() << ": " << status.error_message()
					<< std::endl;
				return IPSEC_FAILURE;
			}
		}

	private:
		std::unique_ptr<P4Runtime::Stub> stub_;
		std::unique_ptr<grpc::ClientReaderWriterInterface<
				::p4::v1::StreamMessageRequest, ::p4::v1::StreamMessageResponse>>
				stream_channel;

};

enum ipsec_status ipsec_set_pipe(void) {
	IPSecP4RuntimeClient client(rt_address);

	/* Set pipe only if not configured */
	if(client.GetPipe() != IPSEC_SUCCESS) {
		std::cout << "Pipeline not configured: Configuring Pipeline\n";
		client.SetPipe();
	} else {
		 std::cout << "Pipeline already configured\n";
	}

	return IPSEC_SUCCESS;
}

enum ipsec_status ipsec_tx_spd_table(enum ipsec_table_op table_op,
				     char dst_ip_addr[16],
				     char  mask[16],
                                     uint32_t match_priority) {
	IPSecP4RuntimeClient client(rt_address);

	return client.P4runtimeIpsecTxSpdTable(table_op, dst_ip_addr, mask, match_priority);
}

enum ipsec_status ipsec_tx_sa_classification_table(enum ipsec_table_op table_op,
						   char dst_ip_addr[16],
                                                   char src_ip_addr[16],
                                                   char crypto_offload,
                                                   uint32_t offloadid,
                                                   uint32_t tunnel_id,
						   uint8_t proto,
						   bool tunnel_mode) {
	IPSecP4RuntimeClient client(rt_address);
	return client.P4runtimeIpsecTxSaClassificationTable(table_op,
							    dst_ip_addr,
							    src_ip_addr,
							    crypto_offload,
							    offloadid,
							    tunnel_id,
							    proto,
							    tunnel_mode);
}

enum ipsec_status ipsec_rx_sa_classification_table(enum ipsec_table_op table_op,
						   char dst_ip_addr[16],
                                                   char src_ip_addr[16],
                                                   uint32_t spi,
                                                   uint32_t offloadid) {
	IPSecP4RuntimeClient client(rt_address);

	return client.P4runtimeIpsecRxSaClassificationTable(table_op,
							    dst_ip_addr,
							    src_ip_addr,
							    spi,
							    offloadid);
}

enum ipsec_status ipsec_rx_post_decrypt_table(enum ipsec_table_op table_op,
					      char crypto_offload,
					      char crypto_status,
					      uint16_t crypto_tag,
					      char dst_ip_addr[16],
					      char dst_ip_mask[16],
					      uint32_t match_priority) {

	IPSecP4RuntimeClient client(rt_address);

	return client.P4runtimeIpsecRxPostDecryptTable(table_op,
						       crypto_offload,
						       crypto_status,
						       crypto_tag,
						       dst_ip_addr,
						       dst_ip_mask,
						       match_priority);
}

enum ipsec_status ipsec_outer_ipv4_encap_mod_table(enum ipsec_table_op table_op,
						   uint32_t mod_blob_ptr,
                                                   char src_ip_addr[16],
                                                   char dst_ip_addr[16],
                                                   uint32_t proto,
                                                   char smac[16],
                                                   char dmac[16]) {
	IPSecP4RuntimeClient client(rt_address);
	return client.P4runtimeIpsecOuterIpv4EncapModTable(table_op,
							   mod_blob_ptr,
							   src_ip_addr,
							   dst_ip_addr,
							   proto,
							   smac,
							   dmac);
}

enum ipsec_status ipsec_outer_ipv4_decap_mod_table(enum ipsec_table_op table_op,
						   uint32_t mod_blob_ptr,
						   char inner_smac[16],
						   char inner_dmac[16])
{
	IPSecP4RuntimeClient client(rt_address);
	return client.P4runtimeIpsecOuterIpv4DecapModTable(table_op,
							   mod_blob_ptr,
							   inner_smac,
							   inner_dmac);

}

#ifdef STANDALONE_TEST
//int ipu_add_port(int argc, char** argv) {
int main(int argc, char** argv) {
	char dst_ip_addr[4]={0xc8, 0x0, 0x0, 0xfc};
	char src_ip_addr[4]={0xc8, 0x1, 0x1, 0xfb};
        char mask [4] = {0xFF, 0xFF, 0xFF, 0xFF};
	int rc;

	ipsec_set_pipe();
	rc = ipsec_tx_spd_table (dst_ip_addr, mask, 1);
	std::cout << rc;
	rc = ipsec_tx_sa_classification_table(dst_ip_addr, src_ip_addr, 1, 1, 1, 6);
	std::cout << rc;
	rc = ipsec_rx_sa_classification_table(dst_ip_addr, src_ip_addr, 0x030003, 0x1234);

	//rc = ipsec_add_with_encap_outer_ipv4_mod(0x1234, dst_ip_addr, src_ip_addr, 1, 0, 0);
	std::cout << rc;
	return 0;
}
#endif
