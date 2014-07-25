/*
 * AppArmor security module
 *
 * This file contains AppArmor label definitions
 *
 * Copyright 2013 Canonical Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 */

#include <linux/audit.h>
#include <linux/seq_file.h>

#include "include/apparmor.h"
#include "include/label.h"
#include "include/policy.h"
#include "include/sid.h"


/*
 * the aa_label represents the set of profiles confining an object
 *
 * Labels maintain a reference count to the set of pointers they reference
 * Labels are ref counted by
 *   tasks and object via the security field/security context off the field
 *   code - will take a ref count on a label if it needs the label
 *          beyond what is possible with an rcu_read_lock.
 *   profiles - each profile is a label
 *   sids - a pinned sid will keep a refcount of the label it is
 *          referencing
 *   objects - inode, files, sockets, ...
 *
 * Labels are not ref counted by the label set, so they maybe removed and
 * freed when no longer in use.
 *
 */

static void free_replacedby(struct aa_replacedby *r)
{
	if (r) {
		/* r->label will not updated any more as r is dead */
		aa_put_label(rcu_dereference_protected(r->label, true));
		kzfree(r);
	}
}

void aa_free_replacedby_kref(struct kref *kref)
{
	struct aa_replacedby *r = container_of(kref, struct aa_replacedby,
					       count);
	free_replacedby(r);
}

struct aa_replacedby *aa_alloc_replacedby(struct aa_label *l)
{
	struct aa_replacedby *r;

	r = kzalloc(sizeof(struct aa_replacedby), GFP_KERNEL);
	if (r) {
		kref_init(&r->count);
		rcu_assign_pointer(r->label, aa_get_label(l));
	}
	return r;
}

/* requires profile list write lock held */
void __aa_update_replacedby(struct aa_label *orig, struct aa_label *new)
{
	struct aa_label *tmp;

	AA_BUG(!orig);
	AA_BUG(!new);
	AA_BUG(!mutex_is_locked(&labels_ns(orig)->lock));

	tmp = rcu_dereference_protected(orig->replacedby->label,
					&labels_ns(orig)->lock);
	rcu_assign_pointer(orig->replacedby->label, aa_get_label(new));
	orig->flags |= FLAG_INVALID;
	aa_put_label(tmp);
}

/* helper fn for label_for_each_confined */
int aa_label_next_confined(struct aa_label *l, int i)
{
	for (; i < l->size; i++) {
		if (!profile_unconfined(l->ent[i]))
			return i;
	}

	return i;
}

static bool profile_in_label(struct aa_profile *profile, struct aa_label *l)
{
	struct aa_profile *p;
	int i;

	AA_BUG(!profile);
	AA_BUG(!l);

	label_for_each(i, l, p) {
		if (p == profile)
			return true;
	}

	return false;
}

void aa_label_destroy(struct aa_label *label)
{
	AA_BUG(!label);

	if (label_invalid(label))
		labelsetstats_dec(labels_set(label), invalid);

	if (!label_isprofile(label)) {
		struct aa_profile *profile;
		int i;

		aa_put_str(label->hname);

		label_for_each(i, label, profile)
			aa_put_profile(profile);
	}

	aa_free_sid(label->sid);
	aa_put_replacedby(label->replacedby);
}

void aa_label_free(struct aa_label *label)
{
	if (!label)
		return;

	aa_label_destroy(label);
	labelstats_inc(freed);
	kzfree(label);
}

static void label_free_rcu(struct rcu_head *head)
{
	struct aa_label *l = container_of(head, struct aa_label, rcu);

	if (l->flags & FLAG_NS_COUNT)
		aa_free_namespace(labels_ns(l));
	else if (label_isprofile(l))
		aa_free_profile(labels_profile(l));
	else
		aa_label_free(l);
}

bool aa_label_remove(struct aa_labelset *ls, struct aa_label *label);
void aa_label_kref(struct kref *kref)
{
	struct aa_label *l = container_of(kref, struct aa_label, count);
	struct aa_namespace *ns = labels_ns(l);

	if (!ns) {
		/* never live, no rcu callback needed, just using the fn */
		label_free_rcu(&l->rcu);
		return;
	}

	(void) aa_label_remove(&ns->labels, l);

	/* TODO: if compound label and not invalid add to reclaim cache */
	call_rcu(&l->rcu, label_free_rcu);
}

bool aa_label_init(struct aa_label *label, int size)
{
	AA_BUG(!label);
	AA_BUG(size < 1);

	label->sid = aa_alloc_sid();
	if (label->sid == AA_SID_INVALID)
		return false;

	label->size = size;
	kref_init(&label->count);
	RB_CLEAR_NODE(&label->node);

	return true;
}

/**
 * aa_label_alloc - allocate a label with a profile vector of @size length
 * @size: size of profile vector in the label
 * @gfp: memory allocation type
 *
 * Returns: new label
 *     else NULL if failed
 */
struct aa_label *aa_label_alloc(int size, gfp_t gfp)
{
	struct aa_label *label;

	AA_BUG(size < 1);

	label = kzalloc(sizeof(*label) + sizeof(struct aa_label *) * (size - 1),
			gfp);
	AA_DEBUG("%s (%p)\n", __func__, label);
	if (!label)
		goto fail;

	if (!aa_label_init(label, size))
		goto fail;

	labelstats_inc(allocated);

	return label;

fail:
	kfree(label);
	labelstats_inc(failed);

	return NULL;
}

static bool __aa_label_remove(struct aa_labelset *ls, struct aa_label *label)
{
	AA_BUG(!ls);
	AA_BUG(!label);
	AA_BUG(write_can_lock(&ls->lock));
	AA_BUG(labels_set(label) != ls);

	if (label_invalid(label))
		labelstats_dec(invalid_intree);
	else
		__label_invalidate(label);

	if (label->flags & FLAG_IN_TREE) {
		labelsetstats_dec(ls, intree);
		rb_erase(&label->node, &ls->root);
		label->flags &= ~FLAG_IN_TREE;
		return true;
	}

	return false;
}

/**
 * aa_label_remove - remove a label from the labelset
 * @ls: set to remove the label from
 * @l: label to remove
 *
 * Returns: true if @l was removed from the tree
 *     else @l was not in tree so it could not be removed
 */
bool aa_label_remove(struct aa_labelset *ls, struct aa_label *l)
{
	unsigned long flags;
	bool res;

	write_lock_irqsave(&ls->lock, flags);
	res = __aa_label_remove(ls, l);
	write_unlock_irqrestore(&ls->lock, flags);

	return res;
}

static bool __aa_label_replace(struct aa_labelset *ls, struct aa_label *old,
			       struct aa_label *new)
{
	AA_BUG(!ls);
	AA_BUG(!old);
	AA_BUG(!new);
	AA_BUG(write_can_lock(&ls->lock));
	AA_BUG(labels_set(old) != ls);
	AA_BUG(new->flags & FLAG_IN_TREE);

	if (label_invalid(old))
		labelstats_dec(invalid_intree);
	else
		__label_invalidate(old);

	if (old->flags & FLAG_IN_TREE) {
		rb_replace_node(&old->node, &new->node, &ls->root);
		old->flags &= ~FLAG_IN_TREE;
		new->flags |= FLAG_IN_TREE;
		return true;
	}

	return false;
}

static struct aa_label *__aa_label_insert(struct aa_labelset *ls,
					  struct aa_label *l);
/**
 * aa_label_replace - replace a label @old with a new version @new
 * @ls: labelset being manipulated
 * @old: label to replace
 * @new: label replacing @old
 *
 * Returns: true if @old was in tree and replaced
 *     else @old was not in tree, and @new was not inserted
 */
bool aa_label_replace(struct aa_labelset *ls, struct aa_label *old,
		      struct aa_label *new)
{
	unsigned long flags;
	bool res;

	write_lock_irqsave(&ls->lock, flags);
	if (!(old->flags & FLAG_IN_TREE)) {
		struct aa_label *l = __aa_label_insert(ls, new);
		res = (l == new);
		aa_put_label(l);
	} else
		res = __aa_label_replace(ls, old, new);
	write_unlock_irqrestore(&ls->lock, flags);

	return res;
}

static int ns_cmp(struct aa_namespace *a, struct aa_namespace *b)
{
	int res;

	AA_BUG(!a);
	AA_BUG(!b);
	AA_BUG(!a->base.name);
	AA_BUG(!b->base.name);

	if (a == b)
		return 0;

	res = a->level - b->level;
	if (res)
		return res;

	return strcmp(a->base.name, b->base.name);
}

/**
 * profile_cmp - profile comparision for set ordering
 * @a: profile to compare (NOT NULL)
 * @b: profile to compare (NOT NULL)
 *
 * Returns: <0  if a < b
 *          ==0 if a == b
 *          >0  if a > b
 */
static int profile_cmp(struct aa_profile *a, struct aa_profile *b)
{
	int res;

	AA_BUG(!a);
	AA_BUG(!b);
	AA_BUG(!a->ns);
	AA_BUG(!b->ns);
	AA_BUG(!a->base.hname);
	AA_BUG(!b->base.hname);

	if (a == b || a->base.hname == b->base.hname)
		return 0;
	res = ns_cmp(a->ns, b->ns);
	if (res)
		return res;

	return strcmp(a->base.hname, b->base.hname);
}

/**
 * label_cmp - label comparision for set ordering
 * @a: label to compare (NOT NULL)
 * @b: label to compare (NOT NULL)
 *
 * Returns: <0  if a < b
 *          ==0 if a == b
 *          >0  if a > b
 */
static int label_cmp(struct aa_label *a, struct aa_label *b)
{
	int i;

	AA_BUG(!a);
	AA_BUG(!b);

	if (a == b)
		return 0;

	for (i = 0; i < a->size && i < b->size; i++) {
		int res = profile_cmp(a->ent[i], b->ent[i]);
		if (res != 0)
			return res;
	}

	return a->size - b->size;
}

/**
 * __aa_label_find - find label @l in label set
 * @ls: set of labels to search (NOT NULL)
 * @l: label to find (NOT NULL)
 *
 * Requires: @ls lock held
 *           caller to hold a valid ref on l
 *
 * Returns: unref counted @l if @l is in tree
 *          unref counted label that is equiv to @l in tree
 *     else NULL if @l or equiv is not in tree
 */
static struct aa_label *__aa_label_find(struct aa_labelset *ls,
					struct aa_label *l)
{
	struct rb_node *node;

	AA_BUG(!ls);
	AA_BUG(!l);

	node = ls->root.rb_node;
	while (node) {
		struct aa_label *this = rb_entry(node, struct aa_label, node);
		int result = label_cmp(l, this);

		if (result < 0)
			node = node->rb_left;
		else if (result > 0)
			node = node->rb_right;
		else
			return this;
	}

	return NULL;
}

/**
 * aa_label_find - find label @l in label set
 * @ls: set of labels to search (NOT NULL)
 * @l: label to find (NOT NULL)
 *
 * Requires: caller to hold a valid ref on l
 *
 * Returns: refcounted @l if @l is in tree
 *          refcounted label that is equiv to @l in tree
 *     else NULL if @l or equiv is not in tree
 */
struct aa_label *aa_label_find(struct aa_labelset *ls, struct aa_label *l)
{
	struct aa_label *label;
	unsigned long flags;

	AA_BUG(!ls);
	AA_BUG(!l);

	read_lock_irqsave(&ls->lock, flags);
	label = aa_get_label(__aa_label_find(ls, l));
	labelstats_inc(sread);
	read_unlock_irqrestore(&ls->lock, flags);

	return label;
}

/**
 * __aa_label_insert - attempt to insert @l into a label set
 * @ls: set of labels to insert @l into (NOT NULL)
 * @l: new label to insert (NOT NULL)
 *
 * Requires: @ls->lock
 *           caller to hold a valid ref on l
 *
 * Returns: ref counted @l if successful in inserting @l
 *          else ref counted equivalent label that is already in the set.
 */
static struct aa_label *__aa_label_insert(struct aa_labelset *ls,
					  struct aa_label *l)
{
	struct rb_node **new, *parent = NULL;

	AA_BUG(!ls);
	AA_BUG(!l);
	AA_BUG(write_can_lock(&ls->lock));
	AA_BUG(l->flags & FLAG_IN_TREE);

	/* Figure out where to put new node */
	new = &ls->root.rb_node;
	while (*new) {
		struct aa_label *this = rb_entry(*new, struct aa_label, node);
		int result = label_cmp(l, this);

		parent = *new;
		if (result == 0) {
			labelsetstats_inc(ls, existing);
			return aa_get_label(this);
		} else if (result < 0)
			new = &((*new)->rb_left);
		else /* (result > 0) */
			new = &((*new)->rb_right);
	}

	/* Add new node and rebalance tree. */
	rb_link_node(&l->node, parent, new);
	rb_insert_color(&l->node, &ls->root);
	l->flags |= FLAG_IN_TREE;
	labelsetstats_inc(ls, insert);
	labelsetstats_inc(ls, intree);

        return 	aa_get_label(l);
}

/**
 * aa_label_insert - insert label @l into @ls or return existing label
 * @ls - labelset to insert @l into
 * @l - label to insert
 *
 * Requires: caller to hold a valid ref on l
 *
 * Returns: ref counted @l if successful in inserting @l
 *     else ref counted equivalent label that is already in the set
 */
struct aa_label *aa_label_insert(struct aa_labelset *ls, struct aa_label *l)
{
	struct aa_label *label;
	unsigned long flags;

	AA_BUG(!ls);
	AA_BUG(!l);

	/* check if label exists before taking lock */
	if (!label_invalid(l)) {
		read_lock_irqsave(&ls->lock, flags);
		label = aa_get_label(__aa_label_find(ls, l));
		read_unlock_irqrestore(&ls->lock, flags);
		labelstats_inc(fread);
		if (label)
			return label;
	}

	write_lock_irqsave(&ls->lock, flags);
	label = __aa_label_insert(ls, l);
	write_unlock_irqrestore(&ls->lock, flags);

	return label;
}


/**
 * aa_labelset_destroy - remove all labels from the label set
 * @ls: label set to cleanup (NOT NULL)
 *
 * Labels that are removed from the set may still exist beyond the set
 * being destroyed depending on their reference counting
 */
void aa_labelset_destroy(struct aa_labelset *ls)
{
	struct rb_node *node;
	unsigned long flags;

	AA_BUG(!ls);

	write_lock_irqsave(&ls->lock, flags);
	for (node = rb_first(&ls->root); node; node = rb_first(&ls->root)) {
		struct aa_label *this = rb_entry(node, struct aa_label, node);
		__aa_label_remove(ls, this);
	}
	write_unlock_irqrestore(&ls->lock, flags);
}

/*
 * @ls: labelset to init (NOT NULL)
 */
void aa_labelset_init(struct aa_labelset *ls)
{
	AA_BUG(!ls);

	rwlock_init(&ls->lock);
	ls->root = RB_ROOT;
	labelstats_init(&ls);
}

/**
 * label_invalidate_labelset - invalidate labels caused to be invalid by @l
 * @ls: labelset to invalidate (NOT NULL)
 * @p: profile that is invalid and causing the invalidation (NOT NULL)
 *
 * Takes invalidated label @l and invalidates all labels in the labelset
 * of @l that contain the invalid profiles in @l that caused @l to become
 * invalid
 */
static void labelset_invalidate(struct aa_labelset *ls, struct aa_profile *p)
{
	unsigned long flags;
	struct rb_node *node;

	AA_BUG(!ls);
	AA_BUG(!p);

	write_lock_irqsave(&ls->lock, flags);

	__labelset_for_each(ls, node) {
		struct aa_label *label = rb_entry(node, struct aa_label, node);
		if (profile_in_label(p, label)) {
			__label_invalidate(label);
			/* TODO: replace invalidated label */
		}
	}

	labelstats_inc(invalid);
	labelstats_inc(invalid_intree);

	write_unlock_irqrestore(&ls->lock, flags);
}

/**
 * __aa_labelset_invalidate_all - invalidate labels in @ns and below
 * @ns: ns to start invalidation at (NOT NULL)
 * @p: profile that is causing invalidation (NOT NULL)
 *
 * Requires: @ns lock be held
 *
 * Invalidates labels based on @p in @ns and any children namespaces.
*/
void __aa_labelset_invalidate_all(struct aa_namespace *ns, struct aa_profile *p)
{
	struct aa_namespace *child;

	AA_BUG(!ns);
	AA_BUG(!p);
	AA_BUG(!mutex_is_locked(&ns->lock));

	labelset_invalidate(&ns->labels, p);

	list_for_each_entry(child, &ns->sub_ns, base.list) {
		mutex_lock(&child->lock);
		__aa_labelset_invalidate_all(child, p);
		mutex_unlock(&child->lock);
	}
}
