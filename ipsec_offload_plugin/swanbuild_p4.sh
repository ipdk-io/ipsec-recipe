#!/bin/sh

ARGUMENT_LIST=(
    "b"
    "t"
    "d"
    "o"
    )

LONGARGUMENT_LIST=(
	"enable_grpc"
    )

# read arguments
opts=$(getopt \
    --longoptions "$(printf "%s," "${LONGARGUMENT_LIST[@]}")" \
    --name "$(basename "$0")" \
    --options  "$(printf "%s:," "${ARGUMENT_LIST[@]}")"  \
    -- "$@"
)

eval set --$opts

build=0
enablegrpc=0
accsdkdir=0
PLATFORM="arm"
DEPS_INSTALL_PATH=""

function error_log() {
     echo "Build strongswan code with ipsec plugin
     Usage: swanbuild OPTION(S) ARG
     or:  swanbuild -t ACC_SDK_DIR [--enable_grpc]  [Downloads strongswan package and build]
          e.g., swanbuild.sh -t /opt/mev/acc/simics-mev-b0-1505 (builds for ARM)
          If --enable_grpc option is provided, code will use grpc instead of sockets
          e.g., swanbuild.sh -t /opt/mev/acc/simics-mev-b0-1505 --enable_grpc (builds for ARM)
          If building natively, pass native option to -t
          e.g., swanbuild.sh -t native --enable_grpc (building on same host)
          e.g., ./swanbuild_p4.sh -t native -o <dependency install dir> --enable_grpc
     or:  swanbuild -d BUILDDIR [Builds strongswan code in the dir provided]
          e.g., swanbuild.sh -d ./strongswan-5.9.4 -t /opt/mev/acc/simics-mev-b0-1505
     VERSION number can be found at: https://download2.strongswan.org/"
	exit
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -t)
            ACC_SDK_DIR=$2
            accsdkdir=1
            build=1
            shift 2
            ;;

        -d)
            BUILDDIR=$2
            shift 2
            ;;
        -o)
            DEPS_INSTALL_PATH=$2
            echo "strongswan dependencies install path is $DEPS_INSTALL_PATH"
            shift 2
            ;;
		--enable_grpc)
			enablegrpc=1
			shift 1
			;;

		*)
               if [[ $accsdkdir -ne 1 ]]; then
                    echo "ERROR: Please provide acc sdk dir path or 'native'"
                    error_log
               fi

			if [[ $accsdkdir -ne 1 && -z $BUILDDIR && $enablegrpc -ne 1 ]]; then
                    error_log
			else
				break
			fi
    esac
done


if [ $ACC_SDK_DIR == "native" ]; then
     PLATFORM="native"
elif [ ! -d $ACC_SDK_DIR ]; then
     echo "ERROR: Invalid acc sdk directory path!!"
     exit
fi
#P4OVS_DEPS_INSTALL is a custom set of binaries shared by SDE team.
#May be docker image need create these dependencies
if [ $enablegrpc -eq 1 ]; then
	export BUILD_WITH_GRPC=ON
     if [ $PLATFORM == "arm" ]; then
	  export GRPC_LIB_PATH=$DEPS_INSTALL_PATH/lib
          export GRPC_LIB64_PATH=$DEPS_INSTALL_PATH/lib
          export GRPC_INCLUDE_PATH=$DEPS_INSTALL_PATH/include
     else
        export GRPC_LIB_PATH=$DEPS_INSTALL_PATH/lib
        export GRPC_LIB64_PATH=$DEPS_INSTALL_PATH/lib64
     	export GRPC_INCLUDE_PATH=$DEPS_INSTALL_PATH/include
     fi

     GRPC_DIR=$DEPS_INSTALL_PATH
     THIRD_PARTY_DIR=$PWD/third-party/
fi

DIR=$BUILDDIR

if [ $build -eq 1 ]; then
     DIR=strongswan
     cd $DIR
     ./autogen.sh
     cd ../
fi

if [ ! -d $DIR ]; then
     echo "ERROR: Invalid directory path!!"
     exit
fi

pwd=$PWD
mkdir -p $pwd/output_$DIR
OUTDIR=$pwd/output_$DIR
OFFLOAD_DIR=$pwd/$IPSECPLUGIN
TMP_FILE=$OUTDIR/.diff.tmp

cat > $TMP_FILE << EOF
--- strongswan-5.9.1/configure	2020-11-10 14:46:58.000000000 -0500
+++ configure	2021-09-01 00:25:37.319740243 -0400
@@ -886,4 +886,6 @@
 USE_KERNEL_PFKEY_FALSE
 USE_KERNEL_PFKEY_TRUE
+USE_INLINE_CRYPTO_IPSEC_FALSE
+USE_INLINE_CRYPTO_IPSEC_TRUE
 USE_KERNEL_NETLINK_FALSE
 USE_KERNEL_NETLINK_TRUE
@@ -1422,4 +1424,5 @@
 enable_xauth_noauth
 enable_kernel_netlink
+enable_ipsec_offload
 enable_kernel_pfkey
 enable_kernel_pfroute
@@ -6439,4 +6442,20 @@
 	enabled_by_default=\${enabled_by_default}" kernel_netlink"
 
+# ipsec offload interfaces / sockets
+# Check whether --enable-ipsec-offload was given.
+if test "\${enable_ipsec_offload+set}" = set; then :
+  enableval=\$enable_ipsec_offload; ipsec_offload_given=true
+		if test x\$enableval = xyes; then
+			ipsec_offload=true
+		 else
+			ipsec_offload=false
+		fi
+else
+  ipsec_offload=false
+		ipsec_offload_given=false
+fi
+
+enabled_by_default=\${disabled_by_default}" ipsec_offload"
+
 # Check whether --enable-kernel-pfkey was given.
 if test "\${enable_kernel_pfkey+set}" = set; then :
@@ -24298,4 +24317,11 @@
 	fi
 
+if test x\$ipsec_offload = xtrue; then
+		c_plugins=\${c_plugins}" ipsec-offload"
+		charon_plugins=\${charon_plugins}" ipsec-offload"
+		cmd_plugins=\${cmd_plugins}" ipsec-offload"
+
+	fi
+
 if test x\$kernel_libipsec = xtrue; then
 		c_plugins=\${c_plugins}" kernel-libipsec"
@@ -25421,4 +25447,12 @@
 fi
 
+ if test x\$ipsec_offload = xtrue; then
+  USE_INLINE_CRYPTO_IPSEC_TRUE=
+  USE_INLINE_CRYPTO_IPSEC_FALSE='#'
+else
+  USE_INLINE_CRYPTO_IPSEC_TRUE='#'
+  USE_INLINE_CRYPTO_IPSEC_FALSE=
+fi
+
  if test x\$kernel_pfkey = xtrue; then
   USE_KERNEL_PFKEY_TRUE=
@@ -26538,5 +26572,5 @@
 # =================
 
-ac_config_files="\$ac_config_files Makefile conf/Makefile fuzz/Makefile man/Makefile init/Makefile init/systemd/Makefile init/systemd-starter/Makefile src/Makefile src/include/Makefile src/libstrongswan/Makefile src/libstrongswan/math/libnttfft/Makefile src/libstrongswan/math/libnttfft/tests/Makefile src/libstrongswan/plugins/aes/Makefile src/libstrongswan/plugins/cmac/Makefile src/libstrongswan/plugins/des/Makefile src/libstrongswan/plugins/blowfish/Makefile src/libstrongswan/plugins/rc2/Makefile src/libstrongswan/plugins/md4/Makefile src/libstrongswan/plugins/md5/Makefile src/libstrongswan/plugins/sha1/Makefile src/libstrongswan/plugins/sha2/Makefile src/libstrongswan/plugins/sha3/Makefile src/libstrongswan/plugins/mgf1/Makefile src/libstrongswan/plugins/fips_prf/Makefile src/libstrongswan/plugins/gmp/Makefile src/libstrongswan/plugins/curve25519/Makefile src/libstrongswan/plugins/rdrand/Makefile src/libstrongswan/plugins/aesni/Makefile src/libstrongswan/plugins/random/Makefile src/libstrongswan/plugins/nonce/Makefile src/libstrongswan/plugins/hmac/Makefile src/libstrongswan/plugins/xcbc/Makefile src/libstrongswan/plugins/x509/Makefile src/libstrongswan/plugins/revocation/Makefile src/libstrongswan/plugins/constraints/Makefile src/libstrongswan/plugins/acert/Makefile src/libstrongswan/plugins/pubkey/Makefile src/libstrongswan/plugins/pkcs1/Makefile src/libstrongswan/plugins/pkcs7/Makefile src/libstrongswan/plugins/pkcs8/Makefile src/libstrongswan/plugins/pkcs12/Makefile src/libstrongswan/plugins/pgp/Makefile src/libstrongswan/plugins/dnskey/Makefile src/libstrongswan/plugins/sshkey/Makefile src/libstrongswan/plugins/pem/Makefile src/libstrongswan/plugins/curl/Makefile src/libstrongswan/plugins/files/Makefile src/libstrongswan/plugins/winhttp/Makefile src/libstrongswan/plugins/unbound/Makefile src/libstrongswan/plugins/soup/Makefile src/libstrongswan/plugins/ldap/Makefile src/libstrongswan/plugins/mysql/Makefile src/libstrongswan/plugins/sqlite/Makefile src/libstrongswan/plugins/padlock/Makefile src/libstrongswan/plugins/openssl/Makefile src/libstrongswan/plugins/wolfssl/Makefile src/libstrongswan/plugins/gcrypt/Makefile src/libstrongswan/plugins/botan/Makefile src/libstrongswan/plugins/agent/Makefile src/libstrongswan/plugins/keychain/Makefile src/libstrongswan/plugins/pkcs11/Makefile src/libstrongswan/plugins/chapoly/Makefile src/libstrongswan/plugins/ctr/Makefile src/libstrongswan/plugins/ccm/Makefile src/libstrongswan/plugins/gcm/Makefile src/libstrongswan/plugins/af_alg/Makefile src/libstrongswan/plugins/drbg/Makefile src/libstrongswan/plugins/ntru/Makefile src/libstrongswan/plugins/bliss/Makefile src/libstrongswan/plugins/bliss/tests/Makefile src/libstrongswan/plugins/newhope/Makefile src/libstrongswan/plugins/newhope/tests/Makefile src/libstrongswan/plugins/test_vectors/Makefile src/libstrongswan/tests/Makefile src/libipsec/Makefile src/libipsec/tests/Makefile src/libsimaka/Makefile src/libtls/Makefile src/libtls/tests/Makefile src/libradius/Makefile src/libtncif/Makefile src/libtnccs/Makefile src/libtnccs/plugins/tnc_tnccs/Makefile src/libtnccs/plugins/tnc_imc/Makefile src/libtnccs/plugins/tnc_imv/Makefile src/libtnccs/plugins/tnccs_11/Makefile src/libtnccs/plugins/tnccs_20/Makefile src/libtnccs/plugins/tnccs_dynamic/Makefile src/libpttls/Makefile src/libimcv/Makefile src/libimcv/plugins/imc_test/Makefile src/libimcv/plugins/imv_test/Makefile src/libimcv/plugins/imc_scanner/Makefile src/libimcv/plugins/imv_scanner/Makefile src/libimcv/plugins/imc_os/Makefile src/libimcv/plugins/imv_os/Makefile src/libimcv/plugins/imc_attestation/Makefile src/libimcv/plugins/imv_attestation/Makefile src/libimcv/plugins/imc_swima/Makefile src/libimcv/plugins/imv_swima/Makefile src/libimcv/plugins/imc_hcd/Makefile src/libimcv/plugins/imv_hcd/Makefile src/charon/Makefile src/charon-nm/Makefile src/charon-tkm/Makefile src/charon-cmd/Makefile src/charon-svc/Makefile src/charon-systemd/Makefile src/libcharon/Makefile src/libcharon/plugins/eap_aka/Makefile src/libcharon/plugins/eap_aka_3gpp/Makefile src/libcharon/plugins/eap_aka_3gpp/tests/Makefile src/libcharon/plugins/eap_aka_3gpp2/Makefile src/libcharon/plugins/eap_dynamic/Makefile src/libcharon/plugins/eap_identity/Makefile src/libcharon/plugins/eap_md5/Makefile src/libcharon/plugins/eap_gtc/Makefile src/libcharon/plugins/eap_sim/Makefile src/libcharon/plugins/eap_sim_file/Makefile src/libcharon/plugins/eap_sim_pcsc/Makefile src/libcharon/plugins/eap_simaka_sql/Makefile src/libcharon/plugins/eap_simaka_pseudonym/Makefile src/libcharon/plugins/eap_simaka_reauth/Makefile src/libcharon/plugins/eap_mschapv2/Makefile src/libcharon/plugins/eap_tls/Makefile src/libcharon/plugins/eap_ttls/Makefile src/libcharon/plugins/eap_peap/Makefile src/libcharon/plugins/eap_tnc/Makefile src/libcharon/plugins/eap_radius/Makefile src/libcharon/plugins/xauth_generic/Makefile src/libcharon/plugins/xauth_eap/Makefile src/libcharon/plugins/xauth_pam/Makefile src/libcharon/plugins/xauth_noauth/Makefile src/libcharon/plugins/tnc_ifmap/Makefile src/libcharon/plugins/tnc_pdp/Makefile src/libcharon/plugins/save_keys/Makefile src/libcharon/plugins/socket_default/Makefile src/libcharon/plugins/socket_dynamic/Makefile src/libcharon/plugins/socket_win/Makefile src/libcharon/plugins/bypass_lan/Makefile src/libcharon/plugins/connmark/Makefile src/libcharon/plugins/counters/Makefile src/libcharon/plugins/forecast/Makefile src/libcharon/plugins/farp/Makefile src/libcharon/plugins/smp/Makefile src/libcharon/plugins/sql/Makefile src/libcharon/plugins/dnscert/Makefile src/libcharon/plugins/ipseckey/Makefile src/libcharon/plugins/medsrv/Makefile src/libcharon/plugins/medcli/Makefile src/libcharon/plugins/addrblock/Makefile src/libcharon/plugins/unity/Makefile src/libcharon/plugins/uci/Makefile src/libcharon/plugins/ha/Makefile src/libcharon/plugins/kernel_netlink/Makefile src/libcharon/plugins/kernel_pfkey/Makefile src/libcharon/plugins/kernel_pfroute/Makefile src/libcharon/plugins/kernel_libipsec/Makefile src/libcharon/plugins/kernel_wfp/Makefile src/libcharon/plugins/kernel_iph/Makefile src/libcharon/plugins/whitelist/Makefile src/libcharon/plugins/ext_auth/Makefile src/libcharon/plugins/lookip/Makefile src/libcharon/plugins/error_notify/Makefile src/libcharon/plugins/certexpire/Makefile src/libcharon/plugins/systime_fix/Makefile src/libcharon/plugins/led/Makefile src/libcharon/plugins/duplicheck/Makefile src/libcharon/plugins/coupling/Makefile src/libcharon/plugins/radattr/Makefile src/libcharon/plugins/osx_attr/Makefile src/libcharon/plugins/p_cscf/Makefile src/libcharon/plugins/android_dns/Makefile src/libcharon/plugins/android_log/Makefile src/libcharon/plugins/stroke/Makefile src/libcharon/plugins/vici/Makefile src/libcharon/plugins/vici/ruby/Makefile src/libcharon/plugins/vici/perl/Makefile src/libcharon/plugins/vici/python/Makefile src/libcharon/plugins/updown/Makefile src/libcharon/plugins/dhcp/Makefile src/libcharon/plugins/load_tester/Makefile src/libcharon/plugins/resolve/Makefile src/libcharon/plugins/attr/Makefile src/libcharon/plugins/attr_sql/Makefile src/libcharon/tests/Makefile src/libtpmtss/Makefile src/libtpmtss/plugins/tpm/Makefile src/stroke/Makefile src/ipsec/Makefile src/starter/Makefile src/starter/tests/Makefile src/_updown/Makefile src/_copyright/Makefile src/scepclient/Makefile src/aikgen/Makefile src/tpm_extendpcr/Makefile src/pki/Makefile src/pki/man/Makefile src/pool/Makefile src/libfast/Makefile src/manager/Makefile src/medsrv/Makefile src/checksum/Makefile src/conftest/Makefile src/pt-tls-client/Makefile src/sw-collector/Makefile src/sec-updater/Makefile src/swanctl/Makefile src/xfrmi/Makefile scripts/Makefile testing/Makefile"
+ac_config_files="\$ac_config_files Makefile conf/Makefile fuzz/Makefile man/Makefile init/Makefile init/systemd/Makefile init/systemd-starter/Makefile src/Makefile src/include/Makefile src/libstrongswan/Makefile src/libstrongswan/math/libnttfft/Makefile src/libstrongswan/math/libnttfft/tests/Makefile src/libstrongswan/plugins/aes/Makefile src/libstrongswan/plugins/cmac/Makefile src/libstrongswan/plugins/des/Makefile src/libstrongswan/plugins/blowfish/Makefile src/libstrongswan/plugins/rc2/Makefile src/libstrongswan/plugins/md4/Makefile src/libstrongswan/plugins/md5/Makefile src/libstrongswan/plugins/sha1/Makefile src/libstrongswan/plugins/sha2/Makefile src/libstrongswan/plugins/sha3/Makefile src/libstrongswan/plugins/mgf1/Makefile src/libstrongswan/plugins/fips_prf/Makefile src/libstrongswan/plugins/gmp/Makefile src/libstrongswan/plugins/curve25519/Makefile src/libstrongswan/plugins/rdrand/Makefile src/libstrongswan/plugins/aesni/Makefile src/libstrongswan/plugins/random/Makefile src/libstrongswan/plugins/nonce/Makefile src/libstrongswan/plugins/hmac/Makefile src/libstrongswan/plugins/xcbc/Makefile src/libstrongswan/plugins/x509/Makefile src/libstrongswan/plugins/revocation/Makefile src/libstrongswan/plugins/constraints/Makefile src/libstrongswan/plugins/acert/Makefile src/libstrongswan/plugins/pubkey/Makefile src/libstrongswan/plugins/pkcs1/Makefile src/libstrongswan/plugins/pkcs7/Makefile src/libstrongswan/plugins/pkcs8/Makefile src/libstrongswan/plugins/pkcs12/Makefile src/libstrongswan/plugins/pgp/Makefile src/libstrongswan/plugins/dnskey/Makefile src/libstrongswan/plugins/sshkey/Makefile src/libstrongswan/plugins/pem/Makefile src/libstrongswan/plugins/curl/Makefile src/libstrongswan/plugins/files/Makefile src/libstrongswan/plugins/winhttp/Makefile src/libstrongswan/plugins/unbound/Makefile src/libstrongswan/plugins/soup/Makefile src/libstrongswan/plugins/ldap/Makefile src/libstrongswan/plugins/mysql/Makefile src/libstrongswan/plugins/sqlite/Makefile src/libstrongswan/plugins/padlock/Makefile src/libstrongswan/plugins/openssl/Makefile src/libstrongswan/plugins/wolfssl/Makefile src/libstrongswan/plugins/gcrypt/Makefile src/libstrongswan/plugins/botan/Makefile src/libstrongswan/plugins/agent/Makefile src/libstrongswan/plugins/keychain/Makefile src/libstrongswan/plugins/pkcs11/Makefile src/libstrongswan/plugins/chapoly/Makefile src/libstrongswan/plugins/ctr/Makefile src/libstrongswan/plugins/ccm/Makefile src/libstrongswan/plugins/gcm/Makefile src/libstrongswan/plugins/af_alg/Makefile src/libstrongswan/plugins/drbg/Makefile src/libstrongswan/plugins/ntru/Makefile src/libstrongswan/plugins/bliss/Makefile src/libstrongswan/plugins/bliss/tests/Makefile src/libstrongswan/plugins/newhope/Makefile src/libstrongswan/plugins/newhope/tests/Makefile src/libstrongswan/plugins/test_vectors/Makefile src/libstrongswan/tests/Makefile src/libipsec/Makefile src/libipsec/tests/Makefile src/libsimaka/Makefile src/libtls/Makefile src/libtls/tests/Makefile src/libradius/Makefile src/libtncif/Makefile src/libtnccs/Makefile src/libtnccs/plugins/tnc_tnccs/Makefile src/libtnccs/plugins/tnc_imc/Makefile src/libtnccs/plugins/tnc_imv/Makefile src/libtnccs/plugins/tnccs_11/Makefile src/libtnccs/plugins/tnccs_20/Makefile src/libtnccs/plugins/tnccs_dynamic/Makefile src/libpttls/Makefile src/libimcv/Makefile src/libimcv/plugins/imc_test/Makefile src/libimcv/plugins/imv_test/Makefile src/libimcv/plugins/imc_scanner/Makefile src/libimcv/plugins/imv_scanner/Makefile src/libimcv/plugins/imc_os/Makefile src/libimcv/plugins/imv_os/Makefile src/libimcv/plugins/imc_attestation/Makefile src/libimcv/plugins/imv_attestation/Makefile src/libimcv/plugins/imc_swima/Makefile src/libimcv/plugins/imv_swima/Makefile src/libimcv/plugins/imc_hcd/Makefile src/libimcv/plugins/imv_hcd/Makefile src/charon/Makefile src/charon-nm/Makefile src/charon-tkm/Makefile src/charon-cmd/Makefile src/charon-svc/Makefile src/charon-systemd/Makefile src/libcharon/Makefile src/libcharon/plugins/eap_aka/Makefile src/libcharon/plugins/eap_aka_3gpp/Makefile src/libcharon/plugins/eap_aka_3gpp/tests/Makefile src/libcharon/plugins/eap_aka_3gpp2/Makefile src/libcharon/plugins/eap_dynamic/Makefile src/libcharon/plugins/eap_identity/Makefile src/libcharon/plugins/eap_md5/Makefile src/libcharon/plugins/eap_gtc/Makefile src/libcharon/plugins/eap_sim/Makefile src/libcharon/plugins/eap_sim_file/Makefile src/libcharon/plugins/eap_sim_pcsc/Makefile src/libcharon/plugins/eap_simaka_sql/Makefile src/libcharon/plugins/eap_simaka_pseudonym/Makefile src/libcharon/plugins/eap_simaka_reauth/Makefile src/libcharon/plugins/eap_mschapv2/Makefile src/libcharon/plugins/eap_tls/Makefile src/libcharon/plugins/eap_ttls/Makefile src/libcharon/plugins/eap_peap/Makefile src/libcharon/plugins/eap_tnc/Makefile src/libcharon/plugins/eap_radius/Makefile src/libcharon/plugins/xauth_generic/Makefile src/libcharon/plugins/xauth_eap/Makefile src/libcharon/plugins/xauth_pam/Makefile src/libcharon/plugins/xauth_noauth/Makefile src/libcharon/plugins/tnc_ifmap/Makefile src/libcharon/plugins/tnc_pdp/Makefile src/libcharon/plugins/save_keys/Makefile src/libcharon/plugins/socket_default/Makefile src/libcharon/plugins/socket_dynamic/Makefile src/libcharon/plugins/socket_win/Makefile src/libcharon/plugins/bypass_lan/Makefile src/libcharon/plugins/connmark/Makefile src/libcharon/plugins/counters/Makefile src/libcharon/plugins/forecast/Makefile src/libcharon/plugins/farp/Makefile src/libcharon/plugins/smp/Makefile src/libcharon/plugins/sql/Makefile src/libcharon/plugins/dnscert/Makefile src/libcharon/plugins/ipseckey/Makefile src/libcharon/plugins/medsrv/Makefile src/libcharon/plugins/medcli/Makefile src/libcharon/plugins/addrblock/Makefile src/libcharon/plugins/unity/Makefile src/libcharon/plugins/uci/Makefile src/libcharon/plugins/ha/Makefile src/libcharon/plugins/kernel_netlink/Makefile src/libcharon/plugins/ipsec_offload/Makefile src/libcharon/plugins/kernel_pfkey/Makefile src/libcharon/plugins/kernel_pfroute/Makefile src/libcharon/plugins/kernel_libipsec/Makefile src/libcharon/plugins/kernel_wfp/Makefile src/libcharon/plugins/kernel_iph/Makefile src/libcharon/plugins/whitelist/Makefile src/libcharon/plugins/ext_auth/Makefile src/libcharon/plugins/lookip/Makefile src/libcharon/plugins/error_notify/Makefile src/libcharon/plugins/certexpire/Makefile src/libcharon/plugins/systime_fix/Makefile src/libcharon/plugins/led/Makefile src/libcharon/plugins/duplicheck/Makefile src/libcharon/plugins/coupling/Makefile src/libcharon/plugins/radattr/Makefile src/libcharon/plugins/osx_attr/Makefile src/libcharon/plugins/p_cscf/Makefile src/libcharon/plugins/android_dns/Makefile src/libcharon/plugins/android_log/Makefile src/libcharon/plugins/stroke/Makefile src/libcharon/plugins/vici/Makefile src/libcharon/plugins/vici/ruby/Makefile src/libcharon/plugins/vici/perl/Makefile src/libcharon/plugins/vici/python/Makefile src/libcharon/plugins/updown/Makefile src/libcharon/plugins/dhcp/Makefile src/libcharon/plugins/load_tester/Makefile src/libcharon/plugins/resolve/Makefile src/libcharon/plugins/attr/Makefile src/libcharon/plugins/attr_sql/Makefile src/libcharon/tests/Makefile src/libtpmtss/Makefile src/libtpmtss/plugins/tpm/Makefile src/stroke/Makefile src/ipsec/Makefile src/starter/Makefile src/starter/tests/Makefile src/_updown/Makefile src/_copyright/Makefile src/scepclient/Makefile src/aikgen/Makefile src/tpm_extendpcr/Makefile src/pki/Makefile src/pki/man/Makefile src/pool/Makefile src/libfast/Makefile src/manager/Makefile src/medsrv/Makefile src/checksum/Makefile src/conftest/Makefile src/pt-tls-client/Makefile src/sw-collector/Makefile src/sec-updater/Makefile src/swanctl/Makefile src/xfrmi/Makefile scripts/Makefile testing/Makefile"
 
 
@@ -27022,4 +27056,8 @@
 Usually this means the macro was only invoked conditionally." "\$LINENO" 5
 fi
+if test -z "\${USE_INLINE_CRYPTO_IPSEC_TRUE}" && test -z "\${USE_INLINE_CRYPTO_IPSEC_FALSE}"; then
+  as_fn_error \$? "conditional \"USE_INLINE_CRYPTO_IPSEC\" was never defined.
+Usually this means the macro was only invoked conditionally." "\$LINENO" 5
+fi
 if test -z "\${USE_KERNEL_PFKEY_TRUE}" && test -z "\${USE_KERNEL_PFKEY_FALSE}"; then
   as_fn_error \$? "conditional \"USE_KERNEL_PFKEY\" was never defined.
@@ -28559,4 +28597,5 @@
     "src/libcharon/plugins/ha/Makefile") CONFIG_FILES="\$CONFIG_FILES src/libcharon/plugins/ha/Makefile" ;;
     "src/libcharon/plugins/kernel_netlink/Makefile") CONFIG_FILES="\$CONFIG_FILES src/libcharon/plugins/kernel_netlink/Makefile" ;;
+    "src/libcharon/plugins/ipsec_offload/Makefile") CONFIG_FILES="\$CONFIG_FILES src/libcharon/plugins/ipsec_offload/Makefile" ;;
     "src/libcharon/plugins/kernel_pfkey/Makefile") CONFIG_FILES="\$CONFIG_FILES src/libcharon/plugins/kernel_pfkey/Makefile" ;;
     "src/libcharon/plugins/kernel_pfroute/Makefile") CONFIG_FILES="\$CONFIG_FILES src/libcharon/plugins/kernel_pfroute/Makefile" ;;
EOF

IPSECPLUGIN=ipsec_offload
DIRECTORY=$DIR/src/libcharon/plugins/$IPSECPLUGIN
rm -rf $DIRECTORY
if [ ! -d $DIRECTORY ]; then
     cp -rf $IPSECPLUGIN $DIRECTORY
fi

USR=$OUTDIR/usr
ETC=$OUTDIR/etc
LIBS_GRPC_ACC=$OUTDIR/libs_grpc_acc
if [ -d $USR ]; then
     rm -rf $USR
fi

if [ -d $ETC ]; then
     rm -rf $ETC
fi

mkdir -p $USR
mkdir -p $ETC

cd $pwd
cd $DIR
patchstatus=`grep -i $IPSECPLUGIN configure | wc -l`
if [ $patchstatus -eq 0 ]; then
     patch -p0 configure < $TMP_FILE
fi

cat > $TMP_FILE << EOF
--- strongswan-5.9.1/src/libcharon/Makefile.in	2020-11-10 14:46:47.000000000 -0500
+++ Makefile.in	2021-09-01 00:25:46.894739841 -0400
@@ -258,4 +258,6 @@
 @USE_KERNEL_NETLINK_TRUE@am__append_108 = plugins/kernel_netlink
 @MONOLITHIC_TRUE@@USE_KERNEL_NETLINK_TRUE@am__append_109 = plugins/kernel_netlink/libstrongswan-kernel-netlink.la
+@USE_INLINE_CRYPTO_IPSEC_TRUE@am__append_110 = plugins/ipsec_offload
+@MONOLITHIC_TRUE@@USE_INLINE_CRYPTO_IPSEC_TRUE@am__append_111 = plugins/ipsec_offload/libstrongswan-ipsec-offload.la
 @USE_KERNEL_LIBIPSEC_TRUE@am__append_110 = plugins/kernel_libipsec
 @MONOLITHIC_TRUE@@USE_KERNEL_LIBIPSEC_TRUE@am__append_111 = plugins/kernel_libipsec/libstrongswan-kernel-libipsec.la
@@ -764,5 +766,6 @@
 	plugins/android_dns plugins/android_log plugins/ha \\
 	plugins/kernel_pfkey plugins/kernel_pfroute \\
-	plugins/kernel_netlink plugins/kernel_libipsec \\
+	plugins/kernel_netlink  plugins/ipsec_offload \\
+	plugins/kernel_libipsec \\
 	plugins/kernel_wfp plugins/kernel_iph plugins/whitelist \\
 	plugins/lookip plugins/error_notify plugins/certexpire \\
EOF

patchstatus=`grep -i $IPSECPLUGIN src/libcharon/Makefile.in | wc -l`
if [ $patchstatus -eq 0 ]; then
     patch -p0 src/libcharon/Makefile.in < $TMP_FILE
fi

cat > $TMP_FILE << EOF
--- strongswan-5.9.1/src/libcharon/Makefile.am	2019-11-11 15:35:20.000000000 -0500
+++ Makefile.am	2021-09-01 00:25:50.010739710 -0400
@@ -580,4 +580,11 @@
 endif
 
+if USE_INLINE_CRYPTO_IPSEC
+  SUBDIRS += plugins/ipsec_offload
+if MONOLITHIC
+  libcharon_la_LIBADD += plugins/ipsec_offload/libstrongswan-ipsec-offload.la
+endif
+endif
+
 if USE_KERNEL_LIBIPSEC
   SUBDIRS += plugins/kernel_libipsec
EOF

patchstatus=`grep -i $IPSECPLUGIN src/libcharon/Makefile.am | wc -l`
if [ $patchstatus -eq 0 ]; then
     patch -p0 src/libcharon/Makefile.am < $TMP_FILE
fi
rm -f $TMP_FILE

if [ $PLATFORM == "arm" ]; then
     if [[ ! -f $ACC_SDK_DIR/environment-setup-aarch64-intel-linux ]]; then
          echo "ERROR: Invalid ARM Toolchain configuration file"
          echo "ERROR: Please check the ACC SDK dir path"
          exit
     fi

     source $ACC_SDK_DIR/environment-setup-aarch64-intel-linux
fi

if [[ -d $THIRD_PARTY_DIR ]]; then
     echo "================== COMPILING THIRD-PARTY DIRECTORY ================"
     cd $THIRD_PARTY_DIR
     ./autogen.sh
     ./configure --enable-grpc
     make uninstall
     make clean
     make -j66
     make install
     cp -r $OFFLOAD_DIR/third-party/  $OFFLOAD_DIR/strongswan/src/libcharon/plugins/ipsec_offload/
     cd $OFFLOAD_DIR/$DIR
     echo "================== THIRD-PARTY COMPILATION DONE ===================="

     pushd ../$DIRECTORY
     PROTO_FILE=bfruntime

     $DEPS_INSTALL_PATH/bin/protoc --cpp_out=. google/rpc/status.proto

     $DEPS_INSTALL_PATH/bin/protoc --cpp_out=. ${PROTO_FILE}.proto
     $DEPS_INSTALL_PATH/bin/protoc --grpc_out=. --plugin=protoc-gen-grpc=$DEPS_INSTALL_PATH/bin/grpc_cpp_plugin ${PROTO_FILE}.proto
     popd
fi

if [[ -n $GRPC_DIR ]]; then
     echo "================== COMPILING GNMI ================"
     cd $OFFLOAD_DIR/ipsec_offload/gnmi/
     ./autogen.sh
     ./configure --enable-grpc
     make
     cp -r $OFFLOAD_DIR/ipsec_offload/gnmi  $OFFLOAD_DIR/strongswan/src/libcharon/plugins/ipsec_offload/
     cd $OFFLOAD_DIR/$DIR
     echo "================== GNMI COMPILATION DONE ===================="

     echo "================== COMPILING P4RUNTIME ================"
     cd $OFFLOAD_DIR/ipsec_offload/p4runtime/
     ./autogen.sh
     ./configure --enable-grpc
     make
     cp -r $OFFLOAD_DIR/ipsec_offload/p4runtime  $OFFLOAD_DIR/strongswan/src/libcharon/plugins/ipsec_offload/
     cd $OFFLOAD_DIR/$DIR
     echo "================== P4RUNTIME COMPILATION DONE ===================="
fi

if [ $PLATFORM == "native" ]; then
     ./configure --prefix=$USR --sysconfdir=$ETC --enable-ipsec-offload --disable-dependency-tracking
else
     ./configure --prefix=$USR --sysconfdir=$ETC --enable-ipsec-offload --host=aarch64-intel-linux
fi

touch -m -t 201512030000 src/libcharon/Makefile.am
touch -m -t 201512030000 src/libcharon/plugins/ipsec_offload/Makefile.am
make clean
make
make install
