/*
 * AppArmor security module
 *
 * This file contains AppArmor functions used to manipulate object security
 * contexts.
 *
 * Copyright (C) 1998-2008 Novell/SUSE
 * Copyright 2009-2010 Canonical Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 *
 * AppArmor sets confinement on every task, via the cred_profile() and
 * which is required and are not allowed to be NULL.  The cred_profile is
 * reference counted.
 *
 * TODO
 * If a task uses change_hat it currently does not return to the old
 * cred or task context but instead creates a new one.  Ideally the task
 * should return to the previous cred if it has not been modified.
 *
 */

#include "include/context.h"
#include "include/policy.h"


/**
 * aa_get_task_profile - Get another task's profile
 * @task: task to query  (NOT NULL)
 *
 * Returns: counted reference to @task's profile
 */
struct aa_profile *aa_get_task_profile(struct task_struct *task)
{
	struct aa_profile *p;

	rcu_read_lock();
	p = aa_get_profile(__aa_cred_profile(task));
	rcu_read_unlock();

	return p;
}

/**
 * aa_alloc_task_ctx - allocate a new task_ctx
 * @flags: gfp flags for allocation
 *
 * Returns: allocated buffer or NULL on failure
 */
struct aa_task_ctx *aa_alloc_task_ctx(gfp_t flags)
{
	return kzalloc(sizeof(struct aa_task_ctx), flags);
}

/**
 * aa_free_task_ctx - free a task_ctx
 * @ctx: task_ctx to free (MAYBE NULL)
 */
void aa_free_task_ctx(struct aa_task_ctx *ctx)
{
	if (ctx) {
		aa_put_profile(ctx->previous);
		aa_put_profile(ctx->onexec);

		kzfree(ctx);
	}
}

/**
 * aa_dup_task_ctx - duplicate a task context, incrementing reference counts
 * @new: a blank task context      (NOT NULL)
 * @old: the task context to copy  (NOT NULL)
 */
void aa_dup_task_ctx(struct aa_task_ctx *new, const struct aa_task_ctx *old)
{
	*new = *old;
	aa_get_profile(new->previous);
	aa_get_profile(new->onexec);
}

/**
 * aa_replace_current_profile - replace the current tasks profiles
 * @profile: new profile  (NOT NULL)
 *
 * Returns: 0 or error on failure
 */
int aa_replace_current_profile(struct aa_profile *profile)
{
	struct aa_profile *old = __aa_current_profile();
	struct cred *new;

	AA_BUG(!profile);

	if (old == profile)
		return 0;

	if (current_cred() != current_real_cred())
		return -EBUSY;

	new  = prepare_creds();
	old = cred_profile(new);
	if (!new)
		return -ENOMEM;

	if (unconfined(profile) || (old->ns != profile->ns))
		/* if switching to unconfined or a different profile namespace
		 * clear out context state
		 */
		aa_clear_task_ctx(current_task_ctx());

	/*
	 * be careful switching cred profile, when racing replacement it
	 * is possible that the cred profile's->proxy->profile is the reference
	 * keeping @profile valid, so make sure to get its reference before
	 * dropping the reference on the cred's profile
	 */
	aa_get_profile(profile);
	aa_put_profile(old);
	cred_profile(new) = profile;

	commit_creds(new);
	return 0;
}

/**
 * aa_set_current_onexec - set the tasks change_profile to happen onexec
 * @profile: system profile to set at exec  (MAYBE NULL to clear value)
 *
 * Returns: 0 or error on failure
 */
int aa_set_current_onexec(struct aa_profile *profile)
{
	struct aa_task_ctx *ctx;

	ctx = current_task_ctx();
	aa_get_profile(profile);
	aa_put_profile(ctx->onexec);
	ctx->onexec = profile;

	return 0;
}

/**
 * aa_set_current_hat - set the current tasks hat
 * @profile: profile to set as the current hat  (NOT NULL)
 * @token: token value that must be specified to change from the hat
 *
 * Do switch of tasks hat.  If the task is currently in a hat
 * validate the token to match.
 *
 * Returns: 0 or error on failure
 */
int aa_set_current_hat(struct aa_profile *profile, u64 token)
{
	struct aa_task_ctx *tctx = current_task_ctx();
	struct cred *new;

	AA_BUG(!profile);

	new = prepare_creds();
	if (!new)
		return -ENOMEM;

	if (!tctx->previous) {
		/* transfer refcount */
		tctx->previous = cred_profile(new);
		tctx->token = token;
	} else if (tctx->token == token) {
		aa_put_profile(cred_profile(new));
	} else {
		/* previous_profile && ctx->token != token */
		abort_creds(new);
		return -EACCES;
	}

	cred_profile(new) = aa_get_newest_profile(profile);
	/* clear exec on switching context */
	aa_put_profile(tctx->onexec);
	tctx->onexec = NULL;

	commit_creds(new);
	return 0;
}

/**
 * aa_restore_previous_profile - exit from hat context restoring the profile
 * @token: the token that must be matched to exit hat context
 *
 * Attempt to return out of a hat to the previous profile.  The token
 * must match the stored token value.
 *
 * Returns: 0 or error of failure
 */
int aa_restore_previous_profile(u64 token)
{
	struct aa_task_ctx *tctx = current_task_ctx();
	struct cred *new;

	if (tctx->token != token)
		return -EACCES;
	/* ignore restores when there is no saved profile */
	if (!tctx->previous)
		return 0;

	new = prepare_creds();
	if (!new)
		return -ENOMEM;

	aa_put_profile(cred_profile(new));
	cred_profile(new) = aa_get_newest_profile(tctx->previous);
	AA_BUG(!cred_profile(new));
	/* clear exec && prev information when restoring to previous context */
	aa_clear_task_ctx(tctx);

	commit_creds(new);

	return 0;
}
