
# IPsec-Recipe Deployment

This document explains how to deploy IPsec-recipe on Intel&reg; IPU E2100 target.

The current version of IPsec deployment is a combined recipe with Linux Networking. A single P4 program is used for both components.

Prerequisites:

- For Linux Networking
  - Download `hw-p4-programs` TAR file compliant with the CI build image and extract it to get `fxp-net_linux-networking` P4 artifacts. Check `README` for bringup guide, and be sure to check `Limitations` for known issues.
  - Follow steps mentioned in deployment guide for bringing up IPU with a custom P4 package.
Modify `load_custom_pkg.sh` with following parameters for linux_networking + ipsec package:

     ```bash
        sed -i 's/sem_num_pages = .*;/sem_num_pages = 28;/g' $CP_INIT_CFG
        sed -i 's/lem_num_pages = .*;/lem_num_pages = 32;/g' $CP_INIT_CFG
        sed -i 's/mod_num_pages = .*;/mod_num_pages = 2;/g' $CP_INIT_CFG
        sed -i 's/cxp_num_pages = .*;/cxp_num_pages = 5;/g' $CP_INIT_CFG
        sed -i 's/acc_apf = 4;/acc_apf = 16;/g' $CP_INIT_CFG
     ```

- Download `IPU_Documentation` TAR file compliant with the CI build image and refer to `Getting Started Guide` on how to install compatible `IDPF driver` on host.

- Before configuring and using IPDK/ipsec-recipe, all networking portion of the setup must be completed. Connectivity between the host, ACC and remote systems must work before attempting any IPsec usage. Refer to the Networking-Recipe (P4 Control Plane) user guide for details on bringing up the networking component: https://ipdk.io/p4cp-userguide/apps/lnw/es2k/es2k-lnw-overlay-vms.html

## IPsec-Recipe Deployment Location

### strongSwan on ACC

This is a simpler deployment scenario where strongSwan and infrap4d both run on ACC. gRPC communication between strongSwan and infrap4d can occur on `localhost` address without any restrictions.

### strongSwan on host
In this case, the strongSwan application (with IPDK/ipsec-recipe plugin) will run on host, and communicate via gRPC to the `infrap4d` process, which runs on the ACC. 

Following deployment details need to be considered:

* In the node policy, enable the communication channel. Details are available here: https://ipdk.io/p4cp-userguide/guides/es2k/enabling-comm-channel.html
* Generate certificates on ACC with COMMON_NAME for the chosen gRPC address. Make sure certificates are copied over to host.
* Launch `infrap4d` on ACC with the chosen gRPC address, not on default `localhost`.
* Note that in networking-recipe, OVS process must also use the `--grpc-addr` flag in order to program the pipeline successfully.
* Update the gRPC address in ipsec_offload.conf file.
* Configure proxies as per your network requirements/settings.

## Run strongSwan

Configure the strongSwan application as per strongSwan user manual and run `ipsec start` on IPU system and remote system.