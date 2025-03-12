// Copyright 2000-2002, 2004-2017, 2021-2023, 2025 Intel Corporation
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef IPSEC_INTEL_PLUGIN_H_
#define IPSEC_INTEL_PLUGIN_H_

#include <library.h>
#include <plugins/plugin.h>

typedef struct ipsec_offload_plugin_t ipsec_offload_plugin_t;

/**
 * plugin interface for ipsec offload plugin
 */
struct ipsec_offload_plugin_t {

  /**
   * implements plugin interface
   */
  plugin_t plugin;
};

#endif /** IPSEC_INTEL_PLUGIN_H_ @}*/
