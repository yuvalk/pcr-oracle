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
read_entry_token(void)
{
	static char id[SDB_LINE_MAX];
	FILE *fp;

	if (!(fp = fopen("/etc/kernel/entry-token", "r"))) {
		debug("Cannot open /etc/kernel/entry-token\n");
		goto fail;
	}

	if (fgets(id, SDB_LINE_MAX, fp))
		id[strcspn(id, "\n")] = 0;

	fclose(fp);
	return id;

fail:
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

		fclose(fp);
		return id;

next_line:
		continue;
	}

fail:
	return NULL;
}

static const char *
read_machine_id(void)
{
	static char id[SDB_LINE_MAX];
	FILE *fp;

	if (!(fp = fopen("/etc/machine-id", "r"))) {
		error("Cannot open /etc/machine_id: %m\n");
		goto fail;
	}

	if (fgets(id, SDB_LINE_MAX, fp))
		id[strcspn(id, "\n")] = 0;

	fclose(fp);
	return id;

fail:
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
		if (!strncmp("linux", line, strlen("linux")))
			dest = result->image;
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

	fclose(fp);
	return true;

fail:
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

static bool
exists_efi_dir(const char *path)
{
	DIR *d = NULL;
	char full_path[PATH_MAX];

	if (path == NULL)
		return false;

	snprintf(full_path, PATH_MAX, "/boot/efi/%s", path);
	if (!(d = opendir(full_path)))
		return false;

	closedir(d);
	return true;
}

static const char *
get_token_id(void)
{
	static const char *token_id = NULL;
	const char *id = NULL;
	const char *image_id = NULL;
	const char *machine_id = NULL;

	/* All IDs are optional (cannot be present), except machine_id */
	token_id = read_entry_token();
	id = read_os_release("ID");
	image_id = read_os_release("IMAGE_ID");
	if (!(machine_id = read_machine_id()))
		return NULL;

	/* The order is not correct, and it is using some heuristics
	 * to find the correct prefix.  Other tools like sdbootutil
	 * seems to use parameters to decide */
	if (token_id == NULL && exists_efi_dir(id))
		token_id = id;
	if (token_id == NULL && exists_efi_dir(image_id))
		token_id = id;
	if (token_id == NULL && exists_efi_dir(machine_id))
		token_id = machine_id;

	return token_id;
}

bool
sdb_get_entry_list(sdb_entry_list_t *result)
{
	const char *token_id = NULL;
	DIR *d = NULL;
	struct dirent *dir;
	char *path = "/boot/efi/loader/entries";

	if (!(token_id = get_token_id()))
		goto fail;

	if (!(d = opendir(path))) {
		error("Cannot read directory contents from /boot/efi/loader/entries: %m\n");
		goto fail;
	}

	while ((dir = readdir(d)) != NULL) {
		if (result->num_entries >= SDB_MAX_ENTRIES)
			break;

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

	closedir(d);
	return true;

fail:
	return false;
}

bool
sdb_is_kernel(const char *application)
{
	const char *token_id;
	const char *prefix = "linux-";
	char path[PATH_MAX];

	if (!(token_id = get_token_id()))
		goto fail;

	snprintf(path, PATH_MAX, "/%s/", token_id);
	if (strncmp(path, application, strlen(path)))
		goto fail;

	strncpy(path, application, PATH_MAX);
	for (char *ptr = strtok(path, "/"); ptr; ptr = strtok(NULL, "/"))
		if (!strncmp(ptr, prefix, strlen(prefix)))
			return true;

fail:
	return false;
}

const char *
sdb_get_next_kernel(void)
{
	static char result[SDB_LINE_MAX];
	sdb_entry_list_t entry_list;

	memset(&entry_list, 0, sizeof(entry_list));
	if (!sdb_get_entry_list(&entry_list)) {
		error("Error generating the list of boot entries\n");
		goto fail;
	}

	strncpy(result, entry_list.entries[0].image, SDB_LINE_MAX);
	return result;

fail:
	return NULL;
}
