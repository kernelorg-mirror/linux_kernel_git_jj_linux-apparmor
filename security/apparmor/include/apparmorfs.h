/*
 * AppArmor security module
 *
 * This file contains AppArmor filesystem definitions.
 *
 * Copyright (C) 1998-2008 Novell/SUSE
 * Copyright 2009-2010 Canonical Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 */

#ifndef __AA_APPARMORFS_H
#define __AA_APPARMORFS_H

#define ARRAY_LEN(ARRAY) (sizeof(ARRAY)/sizeof(*(ARRAY)))

enum aa_fs_type {
	AA_FS_TYPE_BOOLEAN,
	AA_FS_TYPE_STRING,
	AA_FS_TYPE_U64,
	AA_FS_TYPE_FOPS,
	AA_FS_TYPE_DIR,
};

struct aa_fs_entry;

struct aa_fs_entry {
	const char *name;
	struct dentry *dentry;
	umode_t mode;
	enum aa_fs_type v_type;
	union {
		bool boolean;
		char *string;
		unsigned long u64;
		struct aa_fs_entry *files;
	} v;
	const struct file_operations *file_ops;
};

extern const struct file_operations aa_fs_seq_file_ops;

#define AA_FS_FILE_BOOLEAN(_name, _value) \
	{ .name = (_name), .mode = 0444, \
	  .v_type = AA_FS_TYPE_BOOLEAN, .v.boolean = (_value), \
	  .file_ops = &aa_fs_seq_file_ops }
#define AA_FS_FILE_STRING(_name, _value) \
	{ .name = (_name), .mode = 0444, \
	  .v_type = AA_FS_TYPE_STRING, .v.string = (_value), \
	  .file_ops = &aa_fs_seq_file_ops }
#define AA_FS_FILE_U64(_name, _value) \
	{ .name = (_name), .mode = 0444, \
	  .v_type = AA_FS_TYPE_U64, .v.u64 = (_value), \
	  .file_ops = &aa_fs_seq_file_ops }
#define AA_FS_FILE_FOPS(_name, _mode, _fops) \
	{ .name = (_name), .v_type = AA_FS_TYPE_FOPS, \
	  .mode = (_mode), .file_ops = (_fops) }
#define AA_FS_DIR(_name, _value) \
	{ .name = (_name), .v_type = AA_FS_TYPE_DIR, .v.files = (_value) }

extern void __init aa_destroy_aafs(void);

struct aa_profile;
struct aa_namespace;

void __aa_fs_profile_rmdir(struct aa_profile *profile);
int __aa_fs_profile_mkdir(struct aa_profile *profile, struct dentry *parent);
void __aa_fs_namespace_rmdir(struct aa_namespace *ns);
int __aa_fs_namespace_mkdir(struct aa_namespace *ns, struct dentry *parent);

#endif /* __AA_APPARMORFS_H */
