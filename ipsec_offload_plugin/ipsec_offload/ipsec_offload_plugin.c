// Copyright 2000-2002, 2004-2017, 2021-2023 Intel Corporation
// SPDX-License-Identifier: GPL-3.0-or-later

#include <daemon.h>
#include "ipsec_offload_plugin.h"
#include "ipsec_offload.h"
#ifdef ENABLEGRPC
#include "ipsec_grpc_connect.h"
#endif

#ifdef ENABLEGRPC
enum ipsec_status ipsec_grpc_connect();
#endif

typedef struct private_ipsec_offload_plugin_t private_ipsec_offload_plugin_t;

typedef struct ipsec_offload_router_t ipsec_offload_router_t;
/**
 * Class that routes the network packets between TUN device, libipsec and
 * charon's IKE socket.
 */
struct ipsec_offload_router_t {

	/**
	 * Implements kernel_listener_t interface
	 */
	kernel_listener_t listener;

	/**
	 * Destroy the given instance
	 */
	void (*destroy)(ipsec_offload_router_t *this);
};
/**
 * private data of ipsec offload plugin
 */
struct private_ipsec_offload_plugin_t {

	/**
	 * implements plugin interface
	 */
	ipsec_offload_plugin_t public;
	/**
	 * TUN device created by this plugin
	 */
	tun_device_t *tun;

	/**
	 * Packet router
	 */
	ipsec_offload_router_t *router;

};

METHOD(plugin_t, get_name, char*,
	private_ipsec_offload_plugin_t *this)
{
	return "ipsec_offload";
}
/**
 * Create the kernel_libipsec_router_t instance
 */
static bool create_router(private_ipsec_offload_plugin_t *this,
						  plugin_feature_t *feature, bool reg, void *arg)
{
	if (reg)
	{	/* We don't need a route for ipsec_offload to inline crypto  */
		this->router = NULL;
	}
	else
	{
		DESTROY_IF(this->router);
	}
	return TRUE;
}
METHOD(plugin_t, get_features, int,
	private_ipsec_offload_plugin_t *this, plugin_feature_t *features[])
{
	static plugin_feature_t f[] = {
		PLUGIN_CALLBACK(kernel_ipsec_register, ipsec_offload_create),
			PLUGIN_PROVIDE(CUSTOM, "kernel-ipsec"),
		PLUGIN_CALLBACK((plugin_feature_callback_t)create_router, NULL),
			PLUGIN_PROVIDE(CUSTOM, "kernel-libipsec-router"),
				PLUGIN_DEPENDS(CUSTOM, "libcharon-receiver"),
	};
	*features = f;
	return countof(f);
}

METHOD(plugin_t, destroy, void,
	private_ipsec_offload_plugin_t *this)
{
	free(this);
}

/*
 * see header file
 */
plugin_t *ipsec_offload_plugin_create()
{
	private_ipsec_offload_plugin_t *this;
		DBG1(DBG_LIB, "initialization of ipsec offload started");
	INIT(this,
		.public = {
			.plugin = {
				.get_name = _get_name,
				.get_features = _get_features,
				.destroy = _destroy,
			},
		},
	);
	return &this->public.plugin;
}
