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
#include "label.h"

struct aa_sk_cxt {
	struct aa_label *label;
	struct aa_label *peer;
};

#define SK_CXT(X) (X)->sk_security
#define SOCK_CXT(X) SOCK_INODE(X)->i_security
#define DEFINE_AUDIT_NET(NAME, OP, SK, F, T, P)				  \
	struct lsm_network_audit NAME ## _net = { .sk = (SK),		  \
						  .family = (F)};	  \
	DEFINE_AUDIT_DATA(NAME,						  \
			  (SK) ? LSM_AUDIT_DATA_NET : LSM_AUDIT_DATA_NONE,\
			  OP);						  \
	NAME.u.net = &(NAME ## _net);					  \
	aad(&NAME)->net.type = type;					  \
	aad(&NAME)->net.protocol = protocol

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

extern int aa_net_perm(int op, struct aa_label *label, u16 family,
		       int type, int protocol, struct sock *sk);
extern int aa_revalidate_sk(int op, struct sock *sk);

static inline void aa_free_net_rules(struct aa_net *new)
{
	/* NOP */
}

#endif /* __AA_NET_H */
