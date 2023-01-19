AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libstrongswan \
	-I$(top_srcdir)/src/libcharon

AM_CFLAGS = \
	$(PLUGIN_CFLAGS)

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-ipsec-offload.la
else
plugin_LTLIBRARIES = libstrongswan-ipsec-offload.la
endif

libstrongswan_ipsec_offload_la_SOURCES = \
	ipsec_offload_plugin.h ipsec_offload_plugin.c \
	ipsec_offload.h ipsec_offload.c \
	bfruntime.pb.h bfruntime.pb.cc \
	bfruntime.grpc.pb.h bfruntime.grpc.pb.cc \
	ipsec_grpc_connect.h ipsec_grpc_connect.cc

#libstrongswan_intel_ipsec_la_LIBADD = $(top_builddir)/src/libipsec/libipsec.la

#libstrongswan_kernel_libipsec_la_LDFLAGS = -module -avoid-version
