# IPsec-Recipe
The IPsec recipe is an application that enables strongSwan to use [Infrastructure Application Interface](https://ipdk.io/documentation/Interfaces/InfraApp/), specifically the P4Runtime and OpenConfig gRPCs provided by the [Networking-Recipe](https://github.com/ipdk-io/networking-recipe).

The strongSwan plugin available in this repository implements a policy-based IPsec enablement using security policy database (SPD) and security association database (SAD). The P4Runtime client introduces a programmable IPsec flow using P4 language for the SPD and OpenConfig for SAD configurability.

* IPsec recipe is validated only on Intel&reg; IPU E2100 target
* Refer to https://ipdk.io/documentation/Recipes/InlineIPsec/
* YANG model for IPsec SAD: https://github.com/ipdk-io/openconfig-public/blob/master/release/models/ipsec/openconfig-ipsec-offload.yang
* Reference P4 program to enable IPsec on DPDK target: https://github.com/ipdk-io/networking-recipe/tree/main/p4src/Inline_IPsec

strongSwan Integration with Inline Crypto Engine
========================================================
* The user should start and stop the strongSwan services as described in strongSwan manual.
* The strongSwan configuration files must be configured by user as described in 
			https://wiki.strongswan.org/projects/strongswan/wiki/UserDocumentation
* Confirm that the networking-recipe (the `infrap4d` process, which acts as the gRPC server) is running before starting strongSwan services.
* strongSwan hosts (Host-A<---->Host-B) should be connected to negotiate the keys.
* The user should follow best practices followed by opensource community for other control plane related configurations.
 
Getting Started
===================

Clone this repository and install the dependencies

```bash
git clone https://github.com/ipdk-io/ipsec-recipe.git
cd ipsec-recipe
source env_setup_acc.sh
./install_dep_packages_acc.sh
```

Clone strongSwan and switch to version 5.9.3 (Any version can be used but verification has been completed on v5.9.3)

```bash
cd ipsec_offload_plugin/
git clone  https://github.com/strongswan/strongswan.git
cd strongswan/
git checkout tags/5.9.3 -b 5.9.3
cd -
```

Build strongSwan

```bash
./swanbuild_p4.sh -t native -o $DEPS_INSTALL --enable_grpc
```

After successful build, files will be installed in `./output_strongswan` directory.

Compile IPsec P4 files and generate the P4 artifacts (p4info.txt and ipsec.pb.bin). These will be used to set the P4 pipeline. See the [Compiling P4 Programs guide](https://github.com/ipdk-io/networking-recipe/blob/main/docs/guides/es2k/compiling-p4-programs.md) for details. Copy the P4 artifacts (p4info.txt and ipsec.pb.bin) in `/var/tmp/` dir with file name linux_networking.p4info.txt and ipsec_fixed_func.pb.bin.

Generate and install the keys and certificates for TLS authentication. Detailed instructions can be found in the [Generating and Installing TLS Certificates guide](https://github.com/ipdk-io/networking-recipe/blob/main/docs/guides/security/using-tls-certificates.md). The keys and certificates will need to be copied to `/usr/share/stratum/certs` folder.

Configure strongSwan
* Review the server IP addresses, client certificate filename, client key filename, client CA filename and p4 table/action names (as per p4info.txt file) in `ipsec_offload_plugin/ipsec_offload.conf` file.
* Copy the configuration file to `/usr/share/stratum`
* Update the strongSwan configuration files (eg: swanctl.conf). Please refer strongSwan documentation.
* Update the system date and stop StrongSwan service (systemctl stop strongswan.service)

Run StrongSwan

Please refer standard strongSwan user manuals to test IPsec usecases using strongSwan.
