
#AUTOMAKE_OPTIONS = foreign subdir-objects
#ACLOCAL_AMFLAGS = -I m4
ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS} -I m4
#SUBDIRS = external
noinst_LTLIBRARIES=

if IS_GRPC_ENABLED

proto_sources = \
external/gnmi/gnmi.proto \
external/gnmi_ext/gnmi_ext.proto

proto_cpp_sources = \
cpp_out/gnmi/gnmi.pb.cc \
cpp_out/gnmi/gnim.pb.h \
cpp_out/gnmi_ext/gnmi_ext.pb.cc \
cpp_out/gnmi_ext/gnmi_ext.pb.h

proto_grpc_sources = \
cpp_out/gnmi/gnmi.grpc.pb.cc \
cpp_out/gnmi/gnim.grpc.pb.h \
cpp_out/gnmi_ext/gnmi_ext.grpc.pb.cc \
cpp_out/gnmi_ext/gnmi_ext.grpc.pb.h

PROTOFLAGS = -I$(srcdir)/external -I$(srcdir)/external/grpc/third_party/protobuf/src/

BUILT_SOURCES = $(proto_cpp_sources)  $(proto_grpc_sources)

# See http://www.gnu.org/software/automake/manual/html_node/Multiple-Outputs.html
proto_files.ts: $(proto_sources)
	@rm -f proto_files.tmp
	@touch proto_files.tmp
	@mkdir -p $(builddir)/cpp_out
	$(PROTOC) $^ --cpp_out $(builddir)/cpp_out \
	    --grpc_out $(builddir)/cpp_out \
            --plugin=protoc-gen-grpc=$(GRPC_CPP_PLUGIN) $(PROTOFLAGS)
	@mv -f proto_files.tmp $@

$(BUILT_SOURCES): proto_files.ts
## Recover from the removal of $@
	@if test -f $@; then :; else \
	  trap 'rm -rf proto_files.lock proto_files.ts' 1 2 13 15; \
## mkdir is a portable test-and-set
	if mkdir proto_files.lock 2>/dev/null; then \
## This code is being executed by the first process.
	  rm -f proto_files.ts; \
	  $(MAKE) $(AM_MAKEFLAGS) proto_files.ts; \
	  result=$$?; rm -rf proto_files.lock; exit $$result; \
	else \
## This code is being executed by the follower processes.
## Wait until the first process is done.
	  while test -d proto_files.lock; do sleep 1; done; \
## Succeed if and only if the first process succeeded.
	    test -f proto_files.ts; \
	  fi; \
	fi

noinst_LTLIBRARIES += \
libbf_gnmi_protobuf.la \
libbf_gnmi_grpc.la 

nodist_libbf_gnmi_protobuf_la_SOURCES = $(proto_cpp_sources)
nodist_libbf_gnmi_grpc_la_SOURCES = $(proto_grpc_sources)

libbf_gnmi_protobuf_la_CPPFLAGS = $(AM_CPPFLAGS) -I$(builddir)/cpp_out
libbf_gnmi_grpc_la_CPPFLAGS = $(AM_CPPFLAGS) -I$(builddir)/cpp_out

includegnmidir = $(includedir)/gnmi
nodist_includegnmi_HEADERS = \
cpp_out/gnmi/gnmi.pb.h \
cpp_out/gnmi_ext/gnmi_ext.pb.h \
cpp_out/gnmi/gnmi.grpc.pb.h \
cpp_out/gnmi_ext/gnmi_ext.grpc.pb.h

CLEANFILES = $(BUILT_SOURCES) proto_files.ts

endif  # IS_GRPC_ENABLED
