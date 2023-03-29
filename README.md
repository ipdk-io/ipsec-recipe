# ipsec-recipe
StrongSwan plugin implements the p4runtime and openconfig clients to configure IPsec SPD and SAD
to the target devices.
- IPsec recipe is validated on Intel target.
- Refer to https://ipdk.io/documentation/Recipes/InlineIPsec/
- YANG model for IPsec SAD: https://github.com/ipdk-io/openconfig-public/blob/master/release/models/ipsec/openconfig-ipsec-offload.yang
- Reference P4 program to enable IPsec on DPDK target: https://github.com/ipdk-io/networking-recipe/tree/main/p4src/Inline_IPsec

StrongSwan integration with Inline Crypto Engine
========================================================
1. The user should start and stop the strongSwan services as described in strongSwan manual.
2. The StrongSwan configuration files need to be configure by user as described in 
			https://wiki.strongswan.org/projects/strongswan/wiki/UserDocumentation
3. Make sure the infrap4d (openconfig, p4runtime) is running before we start strongSwan services.
4. StrongSwan hosts (Host-A<---->Host-B) should be connected to negotiate the keys.
5. The user should use the best practices followed by opensource community for other control plane related configurations.
 
Build and run StrongSwan on Linux
=====================================================================================================================
	#Clone this repo and build dependency using scripts.
	source env_setup_acc.sh
	./install_dep_packages_acc.sh

	cd ipsec_offload_plugin/
	#clone Strongswan and Switch to version 5.9.3 (Any version can be used but verified on 5.9.3)
	git clone  https://github.com/strongswan/strongswan.git
	cd strongswan/
	git checkout tags/5.9.3 -b 5.9.3
	cd ..

	#build StrongSwan
	./swanbuild_p4.sh -t native -o $DEPS_INSTALL --enable_grpc
	After successful build, files will be installed in ./output_strongswan dir.

	#Configure strongSwan
	Generate files(p4info, pb.bin) used to set p4 pipeline and place it in /var/tmp/
	ls /var/tmp/linux_networking.p4info.txt
	ls /var/tmp/ipsec_fixed_func.pb.bin

	Generate the key and cert using openssl commands.
	update the gnmi server IP and cert,key files path in ipsec_offload.conf and copy it in  /usr/share/stratum
	Update the strongSwan configuration files(eg: swanctl.conf). Please refer strongSwan documentation.
	update the system date and stop StrongSwan service (systemctl stop strongswan.service)

	#Run StrongSwan
	Please refer standard strongSwan user manuals to test IPsec usecases using strongSwan.


