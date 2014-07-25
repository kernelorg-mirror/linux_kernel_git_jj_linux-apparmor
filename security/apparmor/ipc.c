/*
 * AppArmor security module
 *
 * This file contains AppArmor ipc mediation
 *
 * Copyright (C) 1998-2008 Novell/SUSE
 * Copyright 2009-2013 Canonical Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 */

#include <linux/gfp.h>
#include <linux/ptrace.h>

#include "include/audit.h"
#include "include/capability.h"
#include "include/context.h"
#include "include/policy.h"
#include "include/ipc.h"

/**
 * audit_ptrace_mask - convert mask to permission string
 * @buffer: buffer to write string to (NOT NULL)
 * @mask: permission mask to convert
 */
static void audit_ptrace_mask(struct audit_buffer *ab, u32 mask)
{
	switch (mask) {
	case MAY_READ:
		audit_log_string(ab, "read");
		break;
	case MAY_WRITE:
		audit_log_string(ab, "trace");
		break;
	case AA_MAY_BE_READ:
		audit_log_string(ab, "readby");
		break;
	case AA_MAY_BE_TRACED:
		audit_log_string(ab, "tracedby");
		break;
	}
}

/* call back to audit ptrace fields */
static void audit_ptrace_cb(struct audit_buffer *ab, void *va)
{
	struct common_audit_data *sa = va;

	if (aad(sa)->request & AA_PTRACE_PERM_MASK) {
		audit_log_format(ab, " requested_mask=");
		audit_ptrace_mask(ab, aad(sa)->request);

		if (aad(sa)->denied & AA_PTRACE_PERM_MASK) {
			audit_log_format(ab, " denied_mask=");
			audit_ptrace_mask(ab, aad(sa)->denied);
		}
	}
	audit_log_format(ab, " peer=");
	audit_log_untrustedstring(ab, aad(sa)->target);
}

/* TODO: conditionals */
static int profile_ptrace_perm(struct aa_profile *profile,
			       struct aa_profile *peer, u32 request,
			       struct common_audit_data *sa)
{
	struct aa_perms perms;

	/* need because of peer in cross check */
	if (profile_unconfined(profile) ||
	    !PROFILE_MEDIATES(profile, AA_CLASS_PTRACE))
                return 0;

	aad(sa)->target = peer->base.hname;
	aa_profile_match_label(profile, peer->base.hname, AA_CLASS_PTRACE,
			       &perms);
	aa_apply_modes_to_perms(profile, &perms);
	return aa_check_perms(profile, &perms, request, sa, audit_ptrace_cb);
}

static int x_profile_ptrace_perm(struct aa_profile *profile,
				 struct aa_profile *peer, u32 request,
				 struct common_audit_data *sa)
{
	return profile_ptrace_perm(profile, peer, request << PTRACE_PERM_SHIFT,
				   sa);
}

static int cross_ptrace_perm(struct aa_profile *tracer,
			     struct aa_profile *tracee, u32 request,
			     struct common_audit_data *sa)
{
	/* if tracer is unconfined bypass tracee test in cross check */
	if (profile_unconfined(tracer))
		return 0;

	if (PROFILE_MEDIATES(tracer, AA_CLASS_PTRACE))
		return cross_check_profiles(tracer, tracee, profile_ptrace_perm,
					    x_profile_ptrace_perm, request, sa);

	/* policy uses the old style capability check for ptrace */
	if (tracer == tracee)
		return 0;

	aad(sa)->label = &tracer->label;
	aad(sa)->target = tracee->base.hname;
	aad(sa)->request = 0;
	aad(sa)->error = aa_capable(&tracer->label, CAP_SYS_PTRACE, 1);
	return aa_audit(AUDIT_APPARMOR_AUTO, tracer, sa, audit_ptrace_cb);
}

/**
 * aa_may_ptrace - test if tracer task can trace the tracee
 * @tracer: label of the task doing the tracing  (NOT NULL)
 * @tracee: task label to be traced
 * @request: permission request
 *
 * Returns: %0 else error code if permission denied or error
 */
int aa_may_ptrace(struct aa_label *tracer, struct aa_label *tracee,
		  u32 request)
{
	DEFINE_AUDIT_DATA(sa, LSM_AUDIT_DATA_NONE, OP_PTRACE);

	return cross_check_labels_profiles(tracer, tracee, cross_ptrace_perm,
					   request, &sa);
}
