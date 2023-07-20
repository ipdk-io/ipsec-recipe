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
#include <grpcpp/grpcpp.h>
#include <sys/stat.h>
#include "re2/re2.h"
#include "ipsec_grpc_connect.h"
#include "gnmi/cpp_out/gnmi/gnmi.grpc.pb.h"
#include "log_plugin.h"

using grpc::Channel;
using grpc::Status;

using std::nothrow;
using std::string;

extern "C" enum ipsec_status gnmi_init();
extern "C" enum ipsec_status ipsec_grpc_connect();
extern "C" enum ipsec_status ipsec_sa_grpc_write(char * buf, int size);
extern "C" enum ipsec_status ipsec_sa_add(char *buf);
extern "C" enum ipsec_status ipsec_sa_del(int offloadid, bool inbound);
extern "C" enum ipsec_status ipsec_fetch_spi(uint32_t *spi);
extern "C" enum ipsec_status ipsec_subscribe_audit_log();
extern "C" enum ipsec_status ipsec_fetch_audit_log(char *cq_data, int size);
extern "C" void ipsec_grpc_close();

/* text file in key=value format e.g. gnmi_server=127.0.0.1:9339 */
string config_file = "/usr/share/stratum/ipsec_offload.conf";
#define GNMI_SERVER_NAME      "gnmi_server"
#define GNMI_CLIENT_CERT_PATH "cli_cert"
#define GNMI_CLIENT_KEY_PATH  "cli_key"
#define GNMI_CA_CERT_PATH     "ca_cert"

#define SAD_PATH_ELE_NAME1  "ipsec-offload"
#define SAD_PATH_ELE_NAME2  "sad"
#define SAD_PATH_ELE_NAME3  "sad-entry"
#define SAD_PATH_ELE_NAME4  "config"

#define SAD_KEY1_NAME  "offload-id"
#define SAD_KEY2_NAME  "direction"

struct gnmi_ctx {
  string gnmi_server_addr;
  string cli_cert;
  string cli_key;
  string ca_cert;
} gnmi_ctx;

string address = "127.0.0.1:50052";
static std::string spi_path = "/ipsec-offload/ipsec-spi/rx-spi";
static std::unique_ptr< ::grpc::ClientReaderWriterInterface<
       ::gnmi::SubscribeRequest, ::gnmi::SubscribeResponse>> stream_reader_writer;
static ::grpc::ClientContext ctx_p;

enum ipsec_status gnmi_init() {
    bool status;

     std::ifstream cFile (config_file);
     if (cFile.is_open())
     {
         std::string line;
         while(getline(cFile, line))
        {
             line.erase(std::remove_if(line.begin(), line.end(), isspace),
                                  line.end());
             if( line.empty() || line[0] == '#' )
             {
                 continue;
             }
             auto delimiterPos = line.find("=");
             auto name = line.substr(0, delimiterPos);
             auto value = line.substr(delimiterPos + 1);
             std::cout << name << " " << value << '\n';
	     if (name == GNMI_SERVER_NAME)
	         gnmi_ctx.gnmi_server_addr = value;
	     else if (name == GNMI_CLIENT_CERT_PATH)
	         gnmi_ctx.cli_cert = value;
	     else if (name == GNMI_CLIENT_KEY_PATH)
	         gnmi_ctx.cli_key = value;
	     else if (name == GNMI_CA_CERT_PATH)
	         gnmi_ctx.ca_cert = value;
         }
     }
     else
     {
         return IPSEC_FAILURE;
     }
     return IPSEC_SUCCESS;
}

static bool modified_file_perm()
{
    struct stat fs;

    stat(gnmi_ctx.cli_cert.c_str(), &fs);
    if (fs.st_mode != 0x81a4)
      return true;
    stat(gnmi_ctx.cli_key.c_str(), &fs);
    if (fs.st_mode != 0x8180)
      return true;
    stat(gnmi_ctx.ca_cert.c_str(), &fs);
    if (fs.st_mode != 0x81a4)
      return true;

    return false;
}

static void readFile(const std::string& filename, std::string& data)
 {
         std::ifstream file (filename.c_str ());

         if (file.is_open ())
         {
                 std::stringstream ss;
                 ss << file.rdbuf ();
                 file.close ();
                 data = ss.str ();
         }

         return;
 }

class IPSecOffloadPluginGnmi {
  public:
    IPSecOffloadPluginGnmi(const std::string& gnmi_server) {
            stub = ::gnmi::gNMI::NewStub(grpc::CreateChannel(
					 gnmi_server,
					 getChannelCredentials()));
    }

    void AddPathElem(std::string elem_name, std::string elem_kv,
                     ::gnmi::PathElem* elem) {
      elem->set_name(elem_name);
      if (!elem_kv.empty()) {
        std::string key, value;
        RE2::FullMatch(elem_kv, "\\[([^=]+)=([^\\]]+)\\]", &key, &value);
        (*elem->mutable_key())[key] = value;
      }
    }

    void BuildGnmiPath(std::string path_str, ::gnmi::Path* path) {
      re2::StringPiece input(path_str);
      std::string elem_name, elem_kv;
      while (RE2::Consume(&input, "/([^/\\[]+)(\\[([^=]+=[^\\]]+)\\])?", &elem_name,
                          &elem_kv)) {
        auto* elem = path->add_elem();
        AddPathElem(elem_name, elem_kv, elem);
      }
    }

    ::gnmi::SetRequest BuildGnmiSetRequest(std::string path,
					   std::string proto_bytes) {
      ::gnmi::SetRequest req;
      ::gnmi::Update* update;

      update = req.add_update();

      BuildGnmiPath(path, update->mutable_path());
      update->mutable_val()->set_proto_bytes(proto_bytes);
      return req;
    }

    ::gnmi::SubscribeRequest BuildGnmiSubOnchangeRequest(std::string path) {
      ::gnmi::SubscribeRequest sub_req;
      auto* sub_list = sub_req.mutable_subscribe();
      sub_list->set_mode(::gnmi::SubscriptionList::STREAM);
      sub_list->set_updates_only(true);
      auto* sub = sub_list->add_subscription();
      sub->set_mode(::gnmi::ON_CHANGE);
      BuildGnmiPath(path, sub->mutable_path());
      return sub_req;
    }

    bool GnmiSetSA(char *proto_bytes, std::string path) {
      ::grpc::ClientContext ctx;
      ::gnmi::SetRequest req = BuildGnmiSetRequest(path, proto_bytes);
      ::gnmi::SetResponse resp;
      Status status = stub->Set(&ctx, req, &resp);
      if(status.ok())
        return true;
      else
        return false;
    }

static void BuildGnmiDeletePath(::gnmi::Path* path, int offloadid, bool inbound) {
      auto* elem = path->add_elem();
      elem->set_name(SAD_PATH_ELE_NAME1);
      elem = path->add_elem();
      elem->set_name(SAD_PATH_ELE_NAME2);
      elem = path->add_elem();
      elem->set_name(SAD_PATH_ELE_NAME3);
      (*elem->mutable_key())[SAD_KEY1_NAME] = std::to_string(offloadid);
      (*elem->mutable_key())[SAD_KEY2_NAME] = std::to_string(inbound);
      elem = path->add_elem();
      elem->set_name(SAD_PATH_ELE_NAME4);
    }

    ::gnmi::SetRequest BuildGnmiDeleteRequest(int offloadid, bool inbound) {
      ::gnmi::SetRequest req;
      auto* del = req.add_delete_();
      BuildGnmiDeletePath(del, offloadid, inbound);
      return req;
    }

    bool GnmiDelSA(int offloadid, bool inbound) {
      ::grpc::ClientContext ctx;
      ::gnmi::SetRequest req = BuildGnmiDeleteRequest(offloadid, inbound);
      ::gnmi::SetResponse resp;
      Status status = stub->Set(&ctx, req, &resp);
      if(status.ok())
        return true;
      else
        return false;
    }

    ::gnmi::GetRequest BuildGnmiGetRequest(std::string path) {
      ::gnmi::GetRequest req;
      BuildGnmiPath(path, req.add_path());
      req.set_encoding(::gnmi::PROTO);
      ::gnmi::GetRequest::DataType data_type;
      data_type = ::gnmi::GetRequest::ALL;
      req.set_type(data_type);
      return req;
    }

    bool GnmiGetSPI(uint32_t *spi) {
      ::grpc::ClientContext ctx;
      ::gnmi::GetRequest req = BuildGnmiGetRequest(spi_path);
      ::gnmi::GetResponse resp;
      Status status = stub->Get(&ctx, req, &resp);
      if(status.ok()) {
        *spi = resp.mutable_notification(0)->mutable_update(0)->mutable_val()->uint_val();
        return true;
      } else {
        LOGGER->Log("ERROR: failed to get spi");
        return false;
      }
    }

    bool GnmiSubOnChange(std::string path) {
      stream_reader_writer = stub->Subscribe(&ctx_p);
      ::gnmi::SubscribeRequest req = BuildGnmiSubOnchangeRequest(path);
      if (ABSL_PREDICT_TRUE(stream_reader_writer->Write(req)))
        return true;
      else
        LOGGER->Log("ERROR: failed to subscribe for notification");
        return false;
    }

  private:
    std::shared_ptr<::grpc::ChannelCredentials> getChannelCredentials() {
    std::string cert, key, ca;

    if (modified_file_perm())
      return NULL;

    readFile (gnmi_ctx.cli_cert, cert);
    readFile (gnmi_ctx.cli_key, key);
    readFile (gnmi_ctx.ca_cert, ca);

    grpc::SslCredentialsOptions opts =
             {
                ca
               ,key
               ,cert

             };
    std::shared_ptr<::grpc::ChannelCredentials> channel_credentials =
      grpc::SslCredentials(grpc::SslCredentialsOptions(opts));
#if 0
    channel_credentials = grpc::InsecureChannelCredentials();
#endif
    return channel_credentials;
    }

    std::unique_ptr< ::gnmi::gNMI::Stub> stub;
};

std::string getSubscribePath() {
   return "/ipsec-offload";
}

std::string getSadAddPath() {
   return "/ipsec-offload/sad/sad-entry[name=*]/config";
}

std::string getSadDeletePath(int offloadid, bool inbound) {
    std::ostringstream oss;
    oss << "/ipsec-offload/sad/sad-entry[offload-id="
	<< offloadid << "][direction=" << inbound << "]/config";
    return oss.str();
}

enum ipsec_status ipsec_fetch_spi(uint32_t *fetched_spi) {
    bool status;

    IPSecOffloadPluginGnmi client(gnmi_ctx.gnmi_server_addr);
    status = client.GnmiGetSPI(fetched_spi);
    if (status && *fetched_spi != INVALID_SA) {
        return IPSEC_SUCCESS;
    }
    return IPSEC_FAILURE;
}

enum ipsec_status ipsec_subscribe_audit_log() {

    IPSecOffloadPluginGnmi client(gnmi_ctx.gnmi_server_addr);
    std::string path = getSubscribePath();
    bool response = client.GnmiSubOnChange(path);
    if (response == true) {
        return IPSEC_SUCCESS;
    }
    return IPSEC_FAILURE;
}

enum ipsec_status ipsec_fetch_audit_log(char *cq_data, int size) {
    std::string al_resp = "invalid";

    ::gnmi::SubscribeResponse resp;
    std::string value;

    if (stream_reader_writer->Read(&resp) && resp.has_update()) {
      value = resp.mutable_update()->mutable_update(0)->mutable_val()->string_val();
      if (value.size() > size)
	      return IPSEC_FAILURE;
      memcpy(cq_data, value.c_str(), size);
      cq_data[value.size()] = '\0';
      return IPSEC_SUCCESS;
    }

    return IPSEC_FAILURE;
}

enum ipsec_status ipsec_sa_add(char * buf) {
    IPSecOffloadPluginGnmi client(gnmi_ctx.gnmi_server_addr);
    std::string path = getSadAddPath();
    bool response = client.GnmiSetSA(buf, path);
    if (response == true) {
        return IPSEC_SUCCESS;
    }
    return IPSEC_FAILURE;
}

enum ipsec_status ipsec_sa_del(int offloadid, bool inbound) {
    IPSecOffloadPluginGnmi client(gnmi_ctx.gnmi_server_addr);
    std::string path = getSadDeletePath(offloadid, inbound);
    bool response = client.GnmiDelSA(offloadid, inbound);
    if (response == true) {
        return IPSEC_SUCCESS;
    }
    return IPSEC_FAILURE;
}
