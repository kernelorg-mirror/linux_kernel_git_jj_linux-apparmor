/*
 * AppArmor security module
 *
 * This file contains AppArmor network mediation definitions.
 *
 * Copyright (C) 1998-2008 Novell/SUSE
 * Copyright 2009-2012 Canonical Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 */

#ifndef __AA_NET_H
#define __AA_NET_H

#include <net/sock.h>

#include "apparmorfs.h"

/* struct aa_net - network confinement data
 * @allowed: basic network families permissions
 * @audit_network: which network permissions to force audit
 * @quiet_network: which network permissions to quiet rejects
 */
struct aa_net {
	u16 allow[AF_MAX];
	u16 audit[AF_MAX];
	u16 quiet[AF_MAX];
};

extern struct aa_fs_entry aa_fs_entry_network[];

#define DEFINE_AUDIT_NET(NAME, OP, SK, F, T, P)				  \
	struct lsm_network_audit NAME ## _net = { .sk = (SK),		  \
						  .family = (F)};	  \
	DEFINE_AUDIT_DATA(NAME,						  \
			  ((SK) && (F) != AF_UNIX) ? LSM_AUDIT_DATA_NET : \
						     LSM_AUDIT_DATA_NONE, \
			  OP);						  \
	NAME.u.net = &(NAME ## _net);					  \
	aad(&NAME)->net.type = (T);					  \
	aad(&NAME)->net.protocol = (P)

#define DEFINE_AUDIT_SK(NAME, OP, SK)					\
	DEFINE_AUDIT_NET(NAME, OP, SK, (SK)->sk_family, (SK)->sk_type,	\
			 (SK)->sk_protocol)

extern int aa_net_perm(const char *op, struct aa_profile *profile, u16 family,
		       int type, int protocol, struct sock *sk);
extern int aa_revalidate_sk(const char *op, struct sock *sk);

static inline void aa_free_net_rules(struct aa_net *new)
{
	/* NOP */
}

#endif /* __AA_NET_H */
