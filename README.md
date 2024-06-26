
# IPsec-Recipe

The IPsec recipe is an application that enables strongSwan to use [Infrastructure Application Interface](https://ipdk.io/documentation/Interfaces/InfraApp/), specifically the P4Runtime and OpenConfig gRPCs provided by the [Networking-Recipe](https://github.com/ipdk-io/networking-recipe).

The strongSwan plugin available in this repository implements a policy-based IPsec enablement using security policy database (SPD) and security association database (SAD). The P4Runtime client introduces a programmable IPsec flow using P4 language for the SPD and OpenConfig for SAD configurability.

* IPsec recipe is validated only on Intel&reg; IPU E2100 target
* Refer to https://ipdk.io/documentation/Recipes/InlineIPsec/
* YANG model for IPsec offload: https://github.com/ipdk-io/openconfig-public/blob/master/release/models/ipsec/openconfig-ipsec-offload.yang
* Reference P4 program to enable IPsec on DPDK target: https://github.com/ipdk-io/networking-recipe/tree/main/p4src/Inline_IPsec

## strongSwan Integration with Inline Crypto Engine

* The user should start and stop the strongSwan services as described in strongSwan manual.
* strongSwan must be configured by the user as described in
			https://wiki.strongswan.org/projects/strongswan/wiki/UserDocumentation
* Confirm that the networking-recipe (the `infrap4d` process, which acts as the gRPC server) is running before starting strongSwan services.
* strongSwan hosts (Host-A<---->Host-B) must be connected to negotiate the keys.
* You should follow the best practices of the open-source community for other control plane related configurations.

## Getting Started

### Prerequisites

It is assumed that the ES2K IPU SDE dependencies have been installed on the
system. The list of dependencies can be found
in `sde/tools/setup/install_dep.py` file.

Prerequisites for stratum-deps and networking-recipe
are assumed to be installed. Some of them also apply to ipsec-recipe.

Install the following packages for building ipsec-recipe.

For Fedora:

```bash
dnf -y update && \
dnf -y install gmp-devel gettext gettext-devel gperf byacc bison texlive flex
```

For Ubuntu:

```bash
apt -y update && \
apt install -y libgmp-dev gettext libgettextpo-dev gperf byacc bison texlive flex
```

### Build IPsec-Recipe

Clone this repository and install the dependencies

```bash
git clone https://github.com/ipdk-io/ipsec-recipe.git
cd ipsec-recipe
source env_setup_acc.sh
./install_dep_packages_acc.sh
```

Clone strongSwan and switch to version 5.9.3 (any version can be used, but verification has been completed with v5.9.3 on Fedora 33)

```bash
cd ipsec_offload_plugin/
git clone  https://github.com/strongswan/strongswan.git
cd strongswan/
git checkout tags/5.9.3 -b 5.9.3
cd -
```

Build strongSwan

```bash
Note: The strongswan and the plugin gets only info on IP(L3) and L4 layer. It don't have
any info on L2 mac addresses. Since in TUNNEL mode we do have a provision to add/delete
new MAC headers along with IP header, We have to use some manual MAC configuration.
This manual configurations are only needed for standalone IPSec recipe. Once IPSec and
networking recipe are integrated the MAC learning will be automatic.

Search following strings and change the value of inner_smac(MAC address of the tunnel
interface on local host) and inner_dmac(MAC address of the tunnel interface on remote host)
accordingly in the file "ipsec_offload_plugin/ipsec_offload/ipsec_offload.c"
inner_smac[16] = {0x00, 0x01, 0x00, 0x00, 0x03, 0x14};
inner_dmac[16] = {0x84, 0x16, 0x0c, 0xba, 0x90, 0xf0};

./swanbuild_p4.sh -t native -o $DEPS_INSTALL --enable_grpc
```

After successful build, files will be installed in `./output_strongswan` directory.

Compile IPsec P4 files and generate the P4 artifacts (p4info.txt and ipsec.pb.bin). These will be used to set the P4 pipeline. See the [Compiling P4 Programs guide](https://github.com/ipdk-io/networking-recipe/blob/main/docs/guides/es2k/compiling-p4-programs.md) for details. Copy the P4 artifacts (p4info.txt and ipsec.pb.bin) in `/var/tmp/` dir with file name linux_networking.p4info.txt and ipsec_fixed_func.pb.bin.

Generate and copy the file /usr/share/stratum/ipsec_role_config.pb.txt using the [link](https://ipdk.io/p4cp-userguide/guides/p4-role-configuration.html)

Generate and install the keys and certificates for TLS authentication. Detailed instructions can be found in the [Generating and Installing TLS Certificates guide](https://github.com/ipdk-io/networking-recipe/blob/main/docs/guides/security/using-tls-certificates.md). The keys and certificates will need to be copied to `/usr/share/stratum/certs` folder.

Configure strongSwan

* Review the server IP addresses, client certificate filename, client key filename, client CA filename and p4 table/action names (as per p4info.txt file) in `ipsec_offload_plugin/ipsec_offload.conf` file.
* Copy the configuration file to `/usr/share/stratum`
* Update the strongSwan configuration files (eg: swanctl.conf). Please refer strongSwan documentation.
* Update the system date and stop StrongSwan service (systemctl stop strongswan.service)

Run StrongSwan

Please refer standard strongSwan user manuals to test IPsec usecases using strongSwan.
