/*
 *   Copyright (C) 2023 SUSE LLC
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

#ifndef SD_BOOT_H
#define SD_BOOT_H

#include <limits.h>

#define SDB_MAX_ENTRIES 16
#define SDB_LINE_MAX 512

typedef struct sdb_entry_data {
	char	path[PATH_MAX];
	char	sort_key[SDB_LINE_MAX];
	char	machine_id[SDB_LINE_MAX];
	char	version[SDB_LINE_MAX];
	char	options[SDB_LINE_MAX];
	char	initrd[SDB_LINE_MAX];
} sdb_entry_data_t;

typedef struct sdb_entry_list {
	unsigned int		num_entries;
	sdb_entry_data_t	entries[SDB_MAX_ENTRIES];
} sdb_entry_list_t;

extern bool			sdb_get_entry_list(sdb_entry_list_t *result);

#endif /* SD_BOOT_H */
