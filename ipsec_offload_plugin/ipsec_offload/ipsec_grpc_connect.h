// Copyright 2000-2002, 2004-2017, 2021-2023, 2025 Intel Corporation
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef IPSEC_GRPC_CONNECT_H_
#define IPSEC_GRPC_CONNECT_H_

#define NUM_TRIES 20
#define INVALID_SA 0x1000000
#define INVALID_INIT_SA 0x1000001

enum ipsec_status { IPSEC_SUCCESS, IPSEC_DUP_ENTRY, IPSEC_FAILURE = -1 };

enum ipsec_table_op { IPSEC_TABLE_ADD, IPSEC_TABLE_MOD, IPSEC_TABLE_DEL };

#endif  // IPSEC_GRPC_CONNECT_H_
