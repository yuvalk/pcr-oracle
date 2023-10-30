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

#include <assert.h>
#include <dirent.h>
#include <ctype.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/param.h>

#include "sd-boot.h"
#include "util.h"


static const char *
read_entry_token()
{
	static char id[SDB_LINE_MAX];
	FILE *fp;

	if (!(fp = fopen("/etc/kernel/entry-token", "r"))) {
		debug("Cannot open /etc/kernel/entry-token\n");
		goto fail;
	}

	if (fgets(id, SDB_LINE_MAX, fp))
		id[strcspn(id, "\n")] = 0;

	return id;

fail:
	fclose(fp);
	return NULL;
}

static const char *
read_os_release(const char *key)
{
	static char id[128];
	char line[SDB_LINE_MAX];
	unsigned int n, k;
	FILE *fp;

	if (!(fp = fopen("/etc/os-release", "r"))) {
		error("Cannot open /etc/os-release: %m\n");
		goto fail;
	}

	while (fgets(line, SDB_LINE_MAX, fp)) {
		if (strncmp(line, key, strlen(key)))
			goto next_line;

		n = strlen(key);
		while (isspace(line[n]))
			++n;

		if (line[n++] != '=')
			goto next_line;

		while (isspace(line[n]))
			++n;

		if (line[n++] != '"')
			goto next_line;

		k = 0;
		while (line[n] != '"') {
			if (line[n] == '\0')
				goto next_line;
			if (k + 1 >= sizeof(id))
				goto next_line;
			id[k++] = line[n++];
		}
		id[k] = '\0';

		return id;

next_line:
		continue;
	}

fail:
	fclose(fp);
	return NULL;
}

static const char *
read_machine_id()
{
	static char id[SDB_LINE_MAX];
	FILE *fp;

	if (!(fp = fopen("/etc/machine-id", "r"))) {
		error("Cannot open /etc/machine_id: %m\n");
		goto fail;
	}

	if (fgets(id, SDB_LINE_MAX, fp))
		id[strcspn(id, "\n")] = 0;

	return id;

fail:
	fclose(fp);
	return NULL;
}

static bool
read_entry(sdb_entry_data_t *result)
{
	FILE *fp;
	char line[SDB_LINE_MAX];

	if (!(fp = fopen(result->path, "r"))) {
		error("Cannot open %s: %m\n", result->path);
		goto fail;
	}

	while (fgets(line, SDB_LINE_MAX, fp)) {
		char *dest = NULL;

		if (!strncmp("sort-key", line, strlen("sort-key")))
			dest = result->sort_key;
		else
		if (!strncmp("machine-id", line, strlen("machine-id")))
			dest = result->machine_id;
		else
		if (!strncmp("version", line, strlen("version")))
			dest = result->version;
		else
		if (!strncmp("options", line, strlen("options")))
			dest = result->options;
		else
		if (!strncmp("initrd", line, strlen("initrd")))
			dest = result->initrd;
		else
			continue;

		/* Position the index on the value section of the line */
		unsigned int index = 0;
		while (line[++index] != ' ');
		while (line[++index] == ' ');
		strncpy(dest, &line[index], strlen(&line[index]) - 1);
	}

	return true;

fail:
	fclose(fp);
	return false;
}

static int
cmp(int a, int b)
{
	return a - b;
}

static bool
isvalid(char a)
{
	return isalnum(a) || a == '~' || a == '-' || a == '^' || a == '.';
}

static int
natoi(const char *a, unsigned int n)
{
	char line[SDB_LINE_MAX];

	strncpy(line, a, MIN(SDB_LINE_MAX, n));
	return atoi(line);
}

static int
vercmp(const void *va, const void *vb)
{
	/* https://uapi-group.org/specifications/specs/version_format_specification/ */
	/* This code is based on strverscmp_improved from systemd */

	const char *a = va;
	const char *b = vb;
	const char *sep = "~-^.";

	assert(a != NULL);
	assert(b != NULL);

	for(;;) {
		const char *aa, *bb;
		int r;

		while (*a != '\0' && !isvalid(*a))
			a++;
		while (*b != '\0' && !isvalid(*b))
			b++;

		/* The longer string is considered new */
		if (*a == '\0' || *b == '\0')
			return cmp(*a, *b);

		for (int i = 0; i < strlen(sep); i++) {
			char s = sep[i];

			if (*a == s || *b == s) {
				r = cmp(*a != s, *b != s);
				if (r != 0)
					return r;

				a++;
				b++;
			}
		}

		if (isdigit(*a) || isdigit(*b)) {
			for (aa = a; isdigit(*aa); aa++);
			for (bb = b; isdigit(*bb); bb++);

			r = cmp(a != aa, b != bb);
			if (r != 0)
				return r;

			r = cmp(natoi(a, aa - a), natoi(b, bb - b));
			if (r != 0)
				return r;
		} else {
			for (aa = a; isalpha(*aa); aa++);
			for (bb = b; isalpha(*bb); bb++);

			r = cmp(strncmp(a, b, MIN(aa - a, bb - b)), 0);
			if (r != 0)
				return r;

			r = cmp(aa - a, bb - b);
			if (r != 0)
				return r;
		}

		a = aa;
		b = bb;
	}
}

static int
entrycmp(const void *va, const void *vb)
{
	/* https://uapi-group.org/specifications/specs/boot_loader_specification/#sorting */
	int result;
	const sdb_entry_data_t *a = va;
	const sdb_entry_data_t *b = vb;

	result = strcmp(a->sort_key, b->sort_key);

	if (result == 0)
		result = strcmp(a->machine_id, b->machine_id);

	if (result == 0)
		result = vercmp(a->version, b->version);

	/* Reverse the order, so new kernels appears first */
	return -result;
}

bool
sdb_get_entry_list(sdb_entry_list_t *result)
{
	// const char *id = NULL;
	const char *image_id = NULL;
	const char *machine_id = NULL;
	const char *token_id = NULL;
	DIR *d = NULL;
	struct dirent *dir;
	char *path = "/boot/efi/loader/entries";

	memset(result, 0, sizeof(*result));

	/* All IDs are optional (cannot be present), except machine_id */
	token_id = read_entry_token();
	// id = read_os_release("ID");
	image_id = read_os_release("IMAGE_ID");
	if (!(machine_id = read_machine_id()))
		goto fail;

	/* The order is not correct (ID is not used), but is how
	 * sdbootutil seems to work */
	if (token_id == NULL && image_id != NULL)
		token_id = image_id;
	if (token_id == NULL && machine_id != NULL)
		token_id = machine_id;

	if (!(d = opendir(path))) {
		error("Cannot read directory contents from /boot/efi/loader/entries: %m\n");
		goto fail;
	}

	while ((dir = readdir(d)) != NULL) {
		if (strncmp(token_id, dir->d_name, strlen(token_id)))
			continue;

		debug("Bootloader entry %s\n", dir->d_name);

		snprintf(result->entries[result->num_entries].path, PATH_MAX, "%s/%s", path, dir->d_name);
		if (!read_entry(&result->entries[result->num_entries])) {
			error("Cannot read bootloader entry %s\n", dir->d_name);
			continue;
		}

		result->num_entries++;
	}

	qsort(result->entries, result->num_entries, sizeof(result->entries[0]), entrycmp);

	return true;

fail:
	closedir(d);
	return false;
}

