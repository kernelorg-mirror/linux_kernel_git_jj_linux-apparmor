/*
 * AppArmor security module
 *
 * This file contains AppArmor af_unix fine grained mediation
 *
 * Copyright 2014 Canonical Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 */

#include <net/tcp_states.h>

#include "include/af_unix.h"
#include "include/apparmor.h"
#include "include/context.h"
#include "include/file.h"
#include "include/label.h"
#include "include/policy.h"

static inline int unix_fs_perm(int op, u32 mask, struct aa_label *label,
			       struct unix_sock *u)
{
	AA_BUG(!label);
	AA_BUG(!u);
	AA_BUG(!UNIX_FS(u));

	if (!unconfined(label) && LABEL_MEDIATES(label, AA_CLASS_FILE)) {
		/* the sunpath may not be valid for this ns so use the path */
		struct path_cond cond = { u->path.dentry->d_inode->i_uid,
					  u->path.dentry->d_inode->i_mode
		};

		return aa_path_perm(op, label, &u->path, 0, mask & NET_FS_PERMS,
				    &cond);
	}

	return 0;
}

/* passing in state returned by PROFILE_MEDIATES_AF */
static unsigned int match_to_prot(struct aa_profile *profile,
				  unsigned int state, int type, int protocol,
				  const char **info)
{
	u16 buffer[2];
	buffer[0] = cpu_to_be16(type);
	buffer[1] = cpu_to_be16(protocol);
	state = aa_dfa_match_len(profile->policy.dfa, state, (char *) &buffer,
				 4);
	if (!state)
		*info = "failed type and protocol match";
	return state;
}

static unsigned int match_addr(struct aa_profile *profile, unsigned int state,
			       struct sockaddr_un *addr, int addrlen)
{
	if (addr)
		/* include leading \0 */
		state = aa_dfa_match_len(profile->policy.dfa, state,
					 addr->sun_path,
					 unix_addr_len(addrlen));
	else
		state = aa_dfa_match_len(profile->policy.dfa, state, "\x01",
					 1);
	/* todo change to out of band */
	state = aa_dfa_null_transition(profile->policy.dfa, state);
	return state;
}

static unsigned int match_to_sk(struct aa_profile *profile,
				unsigned int state, struct unix_sock *u,
				const char **info)
{
	state = match_to_prot(profile, state, u->sk.sk_type, u->sk.sk_protocol,
			      info);
	if (state) {
		struct sockaddr_un *addr = NULL;
		int len = 0;
		if (u->addr) {
			addr = u->addr->name;
			len = u->addr->len;
		}
		state = match_addr(profile, state, addr, len);
		if (state) {
			state = aa_dfa_null_transition(profile->policy.dfa,
						       state);
			if (!state)
				*info = "failed local label match";
		} else
			*info = "failed local address match";
	}

	return state;
}

#define CMD_ADDR	1
#define CMD_LISTEN	2
#define CMD_ACCEPT	3
#define CMD_OPT		4

static inline unsigned int match_to_cmd(struct aa_profile *profile,
					unsigned int state, struct unix_sock *u,
					char cmd, const char **info)
{
	state = match_to_sk(profile, state, u, info);
	if (state) {
		state = aa_dfa_match_len(profile->policy.dfa, state, &cmd, 1);
		if (!state)
			*info = "failed cmd selection match";
	}

	return state;
}

static inline unsigned int match_to_peer(struct aa_profile *profile,
					 unsigned int state,
					 struct unix_sock *u,
					 struct sockaddr_un *addr, int addrlen,
					 const char **info)
{
	state = match_to_cmd(profile, state, u, CMD_ADDR, info);
	if (state) {
		state = match_addr(profile, state, addr, addrlen);
		if (!state)
			*info = "failed peer address match";
	}
	return state;
}

static int do_perms(struct aa_profile *profile, unsigned int state, u32 request,
		    struct common_audit_data *sa)
{
	struct aa_perms perms;

	AA_BUG(!profile);

	aa_compute_perms(profile->policy.dfa, state, &perms);
	aa_apply_modes_to_perms(profile, &perms);
perms.complain = 0xffffffff;
	return aa_check_perms(profile, &perms, request, sa,
			      audit_net_cb);
}

static int match_label(struct aa_profile *profile, struct aa_profile *peer,
			      unsigned int state, u32 request,
			      struct common_audit_data *sa)
{
	AA_BUG(!profile);
	AA_BUG(!peer);

	aad(sa)->target = aa_peer_name(peer);

	if (state) {
		state = aa_dfa_match(profile->policy.dfa, state, aa_peer_name(peer));
		if (!state)
			aad(sa)->info = "failed peer label match";
	}
	return do_perms(profile, state, request, sa);
}


/* unix sock creation comes before we know if the socket will be an fs
 * socket
 * v6 - semantics are handled by mapping in profile load
 * v7 - semantics require sock create for tasks creating an fs socket.
 */
static int profile_create_perm(struct aa_profile *profile, int family,
			       int type, int protocol)
{
	unsigned int state;

	AA_BUG(!profile);
	AA_BUG(profile_unconfined(profile));

	if ((state = PROFILE_MEDIATES_AF(profile, AF_UNIX))) {
		DEFINE_AUDIT_UNIX(sa, OP_CREATE, NULL, type, protocol);

		state = match_to_prot(profile, state, type, protocol,
				      &aad(&sa)->info);
		return do_perms(profile, state, AA_MAY_CREATE, &sa);
	}

	return aa_profile_af_perm(profile, OP_CREATE, family, type, protocol,
				  NULL);
}

int aa_unix_create_perm(struct aa_label *label, int family, int type,
			int protocol)
{
	struct aa_profile *profile;

	if (unconfined(label))
		return 0;

	return fn_for_each_confined(label, profile,
			profile_create_perm(profile, family, type, protocol));
}


static inline int profile_sk_perm(struct aa_profile *profile, int op,
				  u32 request, struct sock *sk)
{
	unsigned int state;

	AA_BUG(!profile);
	AA_BUG(!sk);
	AA_BUG(UNIX_FS(sk));
	AA_BUG(profile_unconfined(profile));

	state = PROFILE_MEDIATES_AF(profile, AF_UNIX);
	if (state) {
		DEFINE_AUDIT_UNIX(sa, op, sk, sk->sk_type, sk->sk_protocol);

		state = match_to_sk(profile, state, unix_sk(sk),
				    &aad(&sa)->info);
		return do_perms(profile, state, request, &sa);
	}

	return aa_profile_af_perm(profile, op, sk->sk_family, sk->sk_type,
				  sk->sk_protocol, sk);
}

int aa_unix_label_sk_perm(struct aa_label *label, int op, u32 request,
			  struct sock *sk)
{
	struct aa_profile *profile;

	return fn_for_each_confined(label, profile,
			profile_sk_perm(profile, op, request, sk));
}

/* revaliation, get/set attr */
int aa_unix_sock_perm(int op, u32 request, struct socket *sock)
{
	struct aa_label *label = aa_current_label();

	if (unconfined(label))
		return 0;
	if (UNIX_FS(sock->sk))
		return unix_fs_perm(op, request, aa_current_label(),
				    unix_sk(sock->sk));

	return aa_unix_label_sk_perm(label, op, request, sock->sk);
}

static int profile_addr_perm(struct aa_profile *profile, int op, u32 request,
			     struct sock *sk, struct sockaddr *addr,
			     int addrlen)
{
	unsigned int state;

	AA_BUG(!profile);
	AA_BUG(!sk);
	AA_BUG(addr->sa_family != AF_UNIX);
	AA_BUG(profile_unconfined(profile));
	AA_BUG(unix_addr_fs(addr, addrlen));

	state = PROFILE_MEDIATES_AF(profile, AF_UNIX);
	if (state) {
		/* bind for abstract socket */
		DEFINE_AUDIT_UNIX(sa, op, sk, sk->sk_type, sk->sk_protocol);
		aad(&sa)->net.addr = unix_addr(addr);
		aad(&sa)->net.addrlen = addrlen;

		state = match_to_peer(profile, state, unix_sk(sk),
				      unix_addr(addr), addrlen,
				      &aad(&sa)->info);
		return do_perms(profile, state, request, &sa);
	}

	return aa_profile_af_perm(profile, op, sk->sk_family, sk->sk_type,
				  sk->sk_protocol, sk);
}

/* connect, bind */
int aa_unix_addr_perm(int op, u32 request, struct socket *sock,
		      struct sockaddr *address, int addrlen)
{
	struct aa_profile *profile;
	struct aa_label *label = aa_current_label();

	/* unix connections are also covered by the
	 * - unix_stream_connect (stream) and unix_may_send hooks (dgram)
	 * - fs connect/bind are handled by mknod/open
	 */
	if (unconfined(label) || (request & AA_MAY_CONNECT) ||
	    unix_addr_fs(address, addrlen))
		return 0;

	return fn_for_each_confined(label, profile,
			profile_addr_perm(profile, op, request,
					  sock->sk, address, addrlen));
}

static int profile_listen_perm(struct aa_profile *profile, struct sock *sk,
			       int backlog)
{
	unsigned int state;

	AA_BUG(!profile);
	AA_BUG(!sk);
	AA_BUG(UNIX_FS(sk));
	AA_BUG(profile_unconfined(profile));

	state = PROFILE_MEDIATES_AF(profile, AF_UNIX);
	if (state) {
		u16 b = cpu_to_be16(backlog);
		DEFINE_AUDIT_UNIX(sa, OP_LISTEN, sk, sk->sk_type,
				  sk->sk_protocol);

		state = match_to_cmd(profile, state, unix_sk(sk), CMD_LISTEN,
				     &aad(&sa)->info);
		if (state) {
			state = aa_dfa_match_len(profile->policy.dfa, state,
						 (char *) &b, 2);
			if (!state)
				aad(&sa)->info = "failed listen backlog match";
		}
		return do_perms(profile, state, AA_MAY_LISTEN, &sa);
	}

	return aa_profile_af_perm(profile, OP_LISTEN, sk->sk_family,
				  sk->sk_type, sk->sk_protocol, sk);
}

int aa_unix_listen_perm(struct socket *sock, int backlog)
{
	struct aa_profile *profile;
	struct aa_label *label = aa_current_label();

	if (unconfined(label) || UNIX_FS(sock->sk))
		return 0;

	return fn_for_each_confined(label, profile,
			profile_listen_perm(profile, sock->sk, backlog));
}


static inline int profile_accept_perm(struct aa_profile *profile,
				      struct sock *sk,
				      struct sock *newsk)
{
	unsigned int state;

	AA_BUG(!profile);
	AA_BUG(!sk);
	AA_BUG(UNIX_FS(sk));
	AA_BUG(profile_unconfined(profile));

	state = PROFILE_MEDIATES_AF(profile, AF_UNIX);
	if (state) {
		DEFINE_AUDIT_UNIX(sa, OP_ACCEPT, sk, sk->sk_type,
				  sk->sk_protocol);

		state = match_to_cmd(profile, state, unix_sk(sk), CMD_ACCEPT,
				     &aad(&sa)->info);
		return do_perms(profile, state, AA_MAY_ACCEPT, &sa);
	}

	return aa_profile_af_perm(profile, OP_ACCEPT, sk->sk_family,
				  sk->sk_type, sk->sk_protocol, sk);
}

/* ability of sock to connect, not peer address binding */
int aa_unix_accept_perm(struct socket *sock, struct socket *newsock)
{
	struct aa_profile *profile;
	struct aa_label *label = aa_current_label();

	if (unconfined(label) || UNIX_FS(sock->sk))
		return 0;

	return fn_for_each_confined(label, profile,
			profile_accept_perm(profile, sock->sk, newsock->sk));
}


/* dgram handled by unix_may_sendmsg, right to send on stream done at connect
 * could do per msg unix_stream here
 */
/* sendmsg, recvmsg */
int aa_unix_msg_perm(int op, u32 request, struct socket *sock,
		     struct msghdr *msg, int size)
{
	return 0;
}


static int profile_opt_perm(struct aa_profile *profile, int op, u32 request,
			    struct sock *sk, int level, int optname)
{
	unsigned int state;

	AA_BUG(!profile);
	AA_BUG(!sk);
	AA_BUG(UNIX_FS(sk));
	AA_BUG(profile_unconfined(profile));

	state = PROFILE_MEDIATES_AF(profile, AF_UNIX);
	if (state) {
		u16 b = cpu_to_be16(optname);
		DEFINE_AUDIT_UNIX(sa, op, sk, sk->sk_type, sk->sk_protocol);

		state = match_to_cmd(profile, state, unix_sk(sk), CMD_OPT,
				     &aad(&sa)->info);
		if (state) {
			state = aa_dfa_match_len(profile->policy.dfa, state,
						 (char *) &b, 2);
			if (!state)
				aad(&sa)->info = "failed sockopt match";
		}
		return do_perms(profile, state, request, &sa);
	}

	return aa_profile_af_perm(profile, OP_LISTEN, sk->sk_family,
				  sk->sk_type, sk->sk_protocol, sk);
}

int aa_unix_opt_perm(int op, u32 request, struct socket *sock, int level,
		     int optname)
{
	struct aa_profile *profile;
	struct aa_label *label = aa_current_label();

	if (unconfined(label) || UNIX_FS(sock->sk))
		return 0;

	return fn_for_each_confined(label, profile,
			profile_opt_perm(profile, op, request, sock->sk,
					 level, optname));
}


static int profile_peer_perm(struct aa_profile *profile, int op, u32 request,
			     struct sock *sk, struct sock *peer_sk,
			     struct common_audit_data *sa)
{
	unsigned int state;

	AA_BUG(!profile);
	AA_BUG(profile_unconfined(profile));
	AA_BUG(!sk);
	AA_BUG(!peer_sk);
	AA_BUG(UNIX_FS(peer_sk));

	state = PROFILE_MEDIATES_AF(profile, AF_UNIX);
	if (state) {
		struct aa_sk_cxt *peer_cxt = SK_CXT(peer_sk);
		struct aa_profile *peerp;
		struct sockaddr_un *addr = NULL;
		int len = 0;
		if (unix_sk(peer_sk)->addr) {
			addr = unix_sk(peer_sk)->addr->name;
			len = unix_sk(peer_sk)->addr->len;
		}
		state = match_to_peer(profile, state, unix_sk(sk),
				      addr, len, &aad(sa)->info);
		return fn_for_each(peer_cxt->label, peerp,
				   match_label(profile, peerp, state, request,
					       sa));
	}

	return aa_profile_af_perm(profile, op, sk->sk_family, sk->sk_type,
				  sk->sk_protocol, sk);
}

/* Need to do
 * addr, sk for reverse, based off of stored addr, and peer_label

static int profile_peer_perm(struct aa_profile *profile, int op, u32 request,
			     struct sock *sk, struct sock *peer_sk,
			     struct common_audit_data *sa)
{
	peer_label = sk_peer_label(sk);
	sk->addr->path, sk->addr->len;

// on connect the addr is shared newsk gets listening sk addr
	int e = xcheck(aa_unix_peer_perm(label, op, MAY_READ | MAY_WRITE,
					 sock->sk, peer_sk),
		       aa_unix_peer_rev(peer_label, op, MAY_READ | MAY_WRITE,
					sk->addr->path, sk->addr->len,
					 label, sk->addr->path, sk->addr-len)
}
*/

int aa_unix_peer_perm(struct aa_label *label, int op, u32 request,
		      struct sock *sk, struct sock *peer_sk)
{
	AA_BUG(!label);
	AA_BUG(!sk);
	AA_BUG(!peer_sk);

	struct unix_sock *peeru = unix_sk(peer_sk);
	if (!UNIX_FS(peeru)) {
		struct aa_profile *profile;
		DEFINE_AUDIT_UNIX(sa, op, sk, sk->sk_type, sk->sk_protocol);
		aad(&sa)->net.peer_sk = peer_sk;

		/* TODO: ns!!! */
		if (!net_eq(sock_net(sk), sock_net(peer_sk))) {
			printk("WARNING apparmor peer sock not in same ns\n");
		}

		if (unconfined(label))
			return 0;

		return fn_for_each_confined(label, profile,
				profile_peer_perm(profile, op, request, sk,
						  peer_sk, &sa));
	}

	return unix_fs_perm(op, request, label, peeru);
}

int aa_unix_file_perm(struct aa_label *label, int op, u32 request,
		      struct socket *sock)
{
	struct sock *peer_sk;
	int error;

	AA_BUG(!label);
	AA_BUG(!sock);
	AA_BUG(!sock->sk);
	AA_BUG(sock->sk->sk_family != AF_UNIX);

	/* TODO: update sock label with new task label */
	unix_state_lock(sock->sk);
	if (UNIX_FS(sock->sk)) {
		/* not fs to the aa_file_perm code, but file here */
		error = unix_fs_perm(op, request, label, unix_sk(sock->sk));
		goto out;
	}
	peer_sk = unix_peer(sock->sk);
	error = aa_unix_label_sk_perm(label, op, request, sock->sk);
	if (!peer_sk || sock->sk->sk_state != TCP_ESTABLISHED ) {
//	       printk("apparmor: file revalidate of unconnected unix sock\n");
					;
	} else {
//		struct aa_sk_cxt *pcxt = SK_CXT(peer_sk);
		/* TODO: fixme to only use local sock for addr, peer */
/*
		int e = xcheck(aa_unix_peer_perm(label, op,
						 MAY_READ | MAY_WRITE,
						 sock->sk, peer_sk),
			       aa_unix_peer_perm(pcxt->label,
						 op, MAY_READ | MAY_WRITE,
						 peer_sk, sock->sk));
		if (e)
			error = e;
*/
//	       printk("apparmor: file revalidate of connected unix sock\n");
		/* GAH double lock can't be used here
		   unix_state_double_lock(sock->sk, peer_sk);
		   unix_state_double_unlock(sock->sk, peer_sk);
		*/
	}
out:
	unix_state_unlock(sock->sk);

	return error;
}
