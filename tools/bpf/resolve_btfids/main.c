// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

/*
 * Resolve the BTF IDs emitted by include/linux/btf_ids.h.
 *
 * This is kept self-contained because the vendor 4.19 tree carries the
 * kernel-side BTF implementation but an older tools/lib/bpf snapshot.
 */

#define _GNU_SOURCE

#include <elf.h>
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <gelf.h>
#include <inttypes.h>
#include <libelf.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <linux/btf.h>

#define BTF_IDS_SECTION ".BTF_ids"
#define BTF_SECTION ".BTF"
#define BTF_ID_PREFIX "__BTF_ID__"

/* BTF kinds added after the 4.19 UAPI header. */
#ifndef BTF_KIND_FLOAT
#define BTF_KIND_FLOAT 16
#endif
#ifndef BTF_KIND_DECL_TAG
#define BTF_KIND_DECL_TAG 17
#endif
#ifndef BTF_KIND_TYPE_TAG
#define BTF_KIND_TYPE_TAG 18
#endif
#ifndef BTF_KIND_ENUM64
#define BTF_KIND_ENUM64 19
#endif

#define BTF_KIND_SET 255

enum id_kind {
	ID_STRUCT = BTF_KIND_STRUCT,
	ID_UNION = BTF_KIND_UNION,
	ID_TYPEDEF = BTF_KIND_TYPEDEF,
	ID_FUNC = BTF_KIND_FUNC,
	ID_SET = BTF_KIND_SET,
};

struct id_entry {
	enum id_kind kind;
	char *name;
	uint32_t id;
	uint64_t *addresses;
	size_t address_count;
	size_t address_capacity;
	uint64_t set_size;
};

struct btf_view {
	const unsigned char *data;
	size_t data_size;
	const unsigned char *types;
	size_t type_size;
	const unsigned char *strings;
	size_t string_size;
};

struct object {
	const char *path;
	int fd;
	Elf *elf;
	Elf_Data *symbols;
	Elf_Data *ids;
	Elf_Data *btf;
	size_t symbol_section;
	size_t ids_section;
	size_t string_section;
	uint64_t ids_address;
	size_t ids_size;
	struct id_entry *entries;
	size_t entry_count;
	size_t entry_capacity;
};

static int verbose;

static void message(const char *level, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	fprintf(stderr, "%s: ", level);
	vfprintf(stderr, fmt, args);
	fprintf(stderr, "\n");
	va_end(args);
}

static uint16_t read_le16(const void *ptr)
{
	uint16_t value;

	memcpy(&value, ptr, sizeof(value));
	return le16toh(value);
}

static uint32_t read_le32(const void *ptr)
{
	uint32_t value;

	memcpy(&value, ptr, sizeof(value));
	return le32toh(value);
}

static void write_native32(void *ptr, uint32_t value)
{
	memcpy(ptr, &value, sizeof(value));
}

static char *duplicate_string(const char *string)
{
	char *copy = strdup(string);

	if (!copy)
		message("error", "out of memory");
	return copy;
}

static struct id_entry *find_entry(struct object *object,
				   enum id_kind kind, const char *name)
{
	size_t i;

	for (i = 0; i < object->entry_count; i++) {
		struct id_entry *entry = &object->entries[i];

		if (entry->kind == kind && !strcmp(entry->name, name))
			return entry;
	}
	return NULL;
}

static struct id_entry *get_entry(struct object *object,
				  enum id_kind kind, const char *name)
{
	struct id_entry *entry;

	entry = find_entry(object, kind, name);
	if (entry)
		return entry;

	if (object->entry_count == object->entry_capacity) {
		size_t capacity = object->entry_capacity ?
			object->entry_capacity * 2 : 32;
		struct id_entry *entries;

		entries = realloc(object->entries, capacity * sizeof(*entries));
		if (!entries) {
			message("error", "out of memory");
			return NULL;
		}
		object->entries = entries;
		object->entry_capacity = capacity;
	}

	entry = &object->entries[object->entry_count++];
	memset(entry, 0, sizeof(*entry));
	entry->kind = kind;
	entry->name = duplicate_string(name);
	if (!entry->name) {
		object->entry_count--;
		return NULL;
	}
	return entry;
}

static int add_address(struct id_entry *entry, uint64_t address)
{
	if (entry->address_count == entry->address_capacity) {
		size_t capacity = entry->address_capacity ?
			entry->address_capacity * 2 : 4;
		uint64_t *addresses;

		addresses = realloc(entry->addresses,
				   capacity * sizeof(*addresses));
		if (!addresses) {
			message("error", "out of memory");
			return -ENOMEM;
		}
		entry->addresses = addresses;
		entry->address_capacity = capacity;
	}

	entry->addresses[entry->address_count++] = address;
	return 0;
}

static int parse_symbol_name(const char *symbol, enum id_kind *kind,
			     char **name)
{
	static const struct {
		const char *prefix;
		enum id_kind kind;
	} kinds[] = {
		{ "struct__", ID_STRUCT },
		{ "union__", ID_UNION },
		{ "typedef__", ID_TYPEDEF },
		{ "func__", ID_FUNC },
	};
	const char *prefix;
	size_t i;

	if (strncmp(symbol, BTF_ID_PREFIX, sizeof(BTF_ID_PREFIX) - 1))
		return 0;

	prefix = symbol + sizeof(BTF_ID_PREFIX) - 1;
	if (!strncmp(prefix, "set__", sizeof("set__") - 1)) {
		*kind = ID_SET;
		*name = duplicate_string(prefix + sizeof("set__") - 1);
		return *name ? 1 : -ENOMEM;
	}

	for (i = 0; i < sizeof(kinds) / sizeof(kinds[0]); i++) {
		size_t prefix_size = strlen(kinds[i].prefix);
		char *id;
		char *suffix;

		if (strncmp(prefix, kinds[i].prefix, prefix_size))
			continue;

		id = duplicate_string(prefix + prefix_size);
		if (!id)
			return -ENOMEM;

		/*
		 * The final "__<counter>" makes each assembler symbol unique.
		 * Remove it while retaining names that contain a single '_'.
		 */
		suffix = strrchr(id, '_');
		if (!suffix || suffix == id || suffix[-1] != '_') {
			message("error", "malformed BTF ID symbol: %s", symbol);
			free(id);
			return -EINVAL;
		}
		suffix[-1] = '\0';
		if (!id[0]) {
			message("error", "empty BTF ID name: %s", symbol);
			free(id);
			return -EINVAL;
		}

		*kind = kinds[i].kind;
		*name = id;
		return 1;
	}

	message("error", "unsupported BTF ID symbol: %s", symbol);
	return -EINVAL;
}

static int collect_sections(struct object *object)
{
	size_t section_count;
	size_t string_index;
	size_t i;

	if (elf_getshdrnum(object->elf, &section_count) < 0 ||
	    elf_getshdrstrndx(object->elf, &string_index) < 0) {
		message("error", "cannot enumerate ELF sections: %s",
			elf_errmsg(-1));
		return -EINVAL;
	}

	for (i = 1; i < section_count; i++) {
		Elf_Scn *section = elf_getscn(object->elf, i);
		Elf_Data *data;
		GElf_Shdr header;
		const char *name;

		if (!section || !gelf_getshdr(section, &header)) {
			message("error", "cannot read ELF section %zu", i);
			return -EINVAL;
		}

		name = elf_strptr(object->elf, string_index, header.sh_name);
		data = elf_getdata(section, NULL);
		if (!name || !data) {
			message("error", "cannot read ELF section %zu data", i);
			return -EINVAL;
		}

		if (header.sh_type == SHT_SYMTAB) {
			object->symbols = data;
			object->symbol_section = i;
			object->string_section = header.sh_link;
		} else if (!strcmp(name, BTF_IDS_SECTION)) {
			object->ids = data;
			object->ids_section = i;
			object->ids_address = header.sh_addr;
			object->ids_size = data->d_size;
		} else if (!strcmp(name, BTF_SECTION)) {
			object->btf = data;
		}
	}

	if (!object->symbols) {
		message("error", "ELF is missing SHT_SYMTAB");
		return -ENOENT;
	}

	return 0;
}

static int symbol_address(struct object *object, uint64_t value,
			  size_t *offset)
{
	uint64_t relative;

	if (value < object->ids_address) {
		message("error", "BTF ID address is before %s", BTF_IDS_SECTION);
		return -EINVAL;
	}

	relative = value - object->ids_address;
	if (relative > object->ids_size ||
	    object->ids_size - relative < sizeof(uint32_t) ||
	    relative % sizeof(uint32_t)) {
		message("error", "BTF ID address is outside %s", BTF_IDS_SECTION);
		return -EINVAL;
	}

	*offset = (size_t)relative;
	return 0;
}

static int collect_symbols(struct object *object)
{
	Elf_Scn *section;
	GElf_Shdr header;
	size_t count;
	size_t i;

	section = elf_getscn(object->elf, object->symbol_section);
	if (!section || !gelf_getshdr(section, &header) || !header.sh_entsize) {
		message("error", "cannot read ELF symbol table");
		return -EINVAL;
	}

	count = header.sh_size / header.sh_entsize;
	for (i = 0; i < count; i++) {
		GElf_Sym symbol;
		const char *name;
		enum id_kind kind;
		char *id_name = NULL;
		struct id_entry *entry;
		size_t offset;
		int parsed;

		if (!gelf_getsym(object->symbols, i, &symbol))
			return -EINVAL;
		if (symbol.st_shndx != object->ids_section)
			continue;

		name = elf_strptr(object->elf, object->string_section,
				  symbol.st_name);
		if (!name)
			return -EINVAL;

		parsed = parse_symbol_name(name, &kind, &id_name);
		if (parsed <= 0) {
			if (parsed < 0)
				return parsed;
			continue;
		}

		if (symbol_address(object, symbol.st_value, &offset)) {
			free(id_name);
			return -EINVAL;
		}

		entry = get_entry(object, kind, id_name);
		free(id_name);
		if (!entry)
			return -ENOMEM;

		if (kind == ID_SET) {
			if (entry->address_count) {
				message("error", "duplicate BTF ID set: %s",
					entry->name);
				return -EINVAL;
			}
			if (symbol.st_size < sizeof(uint32_t) ||
			    symbol.st_size % sizeof(uint32_t)) {
				message("error", "malformed BTF ID set: %s",
					entry->name);
				return -EINVAL;
			}
			entry->set_size = symbol.st_size;
		}

		if (add_address(entry, offset))
			return -ENOMEM;
	}

	return 0;
}

static int load_file(const char *path, unsigned char **data, size_t *size)
{
	struct stat statbuf;
	size_t done = 0;
	int fd;

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		message("error", "cannot open BTF file %s: %s",
			path, strerror(errno));
		return -errno;
	}
	if (fstat(fd, &statbuf) || statbuf.st_size < 0 ||
	    (uintmax_t)statbuf.st_size > SIZE_MAX) {
		message("error", "cannot stat BTF file %s: %s",
			path, strerror(errno));
		close(fd);
		return -EINVAL;
	}

	*size = (size_t)statbuf.st_size;
	*data = malloc(*size);
	if (!*data) {
		close(fd);
		return -ENOMEM;
	}

	while (done < *size) {
		ssize_t count = read(fd, *data + done, *size - done);

		if (count <= 0) {
			message("error", "cannot read BTF file %s: %s",
				path, count < 0 ? strerror(errno) : "short read");
			free(*data);
			*data = NULL;
			close(fd);
			return -EIO;
		}
		done += count;
	}
	close(fd);
	return 0;
}

static int btf_view_init(struct btf_view *view, const void *data, size_t size)
{
	const unsigned char *raw = data;
	uint32_t header_size;
	uint32_t type_offset;
	uint32_t type_size;
	uint32_t string_offset;
	uint32_t string_size;
	uint16_t magic;
	uint8_t version;

	if (size < sizeof(struct btf_header))
		return -EINVAL;

	magic = read_le16(raw);
	version = raw[2];
	header_size = read_le32(raw + 4);
	type_offset = read_le32(raw + 8);
	type_size = read_le32(raw + 12);
	string_offset = read_le32(raw + 16);
	string_size = read_le32(raw + 20);

	if (magic != BTF_MAGIC || version != BTF_VERSION ||
	    header_size < sizeof(struct btf_header) || header_size > size ||
	    type_offset > size - header_size ||
	    type_size > size - header_size - type_offset ||
	    string_offset > size - header_size ||
	    string_size > size - header_size - string_offset ||
	    !string_size) {
		message("error", "malformed BTF data");
		return -EINVAL;
	}

	view->data = raw;
	view->data_size = size;
	view->types = raw + header_size + type_offset;
	view->type_size = type_size;
	view->strings = raw + header_size + string_offset;
	view->string_size = string_size;
	return 0;
}

static const char *btf_string(const struct btf_view *view, uint32_t offset)
{
	const unsigned char *start;

	if (offset >= view->string_size)
		return NULL;
	start = view->strings + offset;
	if (!memchr(start, '\0', view->string_size - offset))
		return NULL;
	return (const char *)start;
}

static int btf_record_size(uint32_t kind, uint32_t vlen, size_t *size)
{
	size_t extra = 0;
	size_t item_size = 0;

	switch (kind) {
	case BTF_KIND_INT:
		extra = sizeof(uint32_t);
		break;
	case BTF_KIND_ARRAY:
		extra = sizeof(struct btf_array);
		break;
	case BTF_KIND_STRUCT:
	case BTF_KIND_UNION:
		item_size = sizeof(struct btf_member);
		break;
	case BTF_KIND_ENUM:
		item_size = sizeof(struct btf_enum);
		break;
	case BTF_KIND_FUNC_PROTO:
		item_size = sizeof(struct btf_param);
		break;
	case BTF_KIND_VAR:
		extra = sizeof(struct btf_var);
		break;
	case BTF_KIND_DATASEC:
		item_size = sizeof(struct btf_var_secinfo);
		break;
	case BTF_KIND_DECL_TAG:
		extra = sizeof(uint32_t);
		break;
	case BTF_KIND_ENUM64:
		item_size = sizeof(uint32_t) * 3;
		break;
	case BTF_KIND_PTR:
	case BTF_KIND_FWD:
	case BTF_KIND_TYPEDEF:
	case BTF_KIND_VOLATILE:
	case BTF_KIND_CONST:
	case BTF_KIND_RESTRICT:
	case BTF_KIND_FUNC:
	case BTF_KIND_FLOAT:
	case BTF_KIND_TYPE_TAG:
		break;
	default:
		message("error", "unsupported BTF kind %u", kind);
		return -EINVAL;
	}

	if (vlen && item_size > (SIZE_MAX - sizeof(struct btf_type)) / vlen)
		return -EOVERFLOW;
	extra += item_size * vlen;
	if (extra > SIZE_MAX - sizeof(struct btf_type))
		return -EOVERFLOW;
	*size = sizeof(struct btf_type) + extra;
	return 0;
}

static void resolve_type(struct object *object, enum id_kind kind,
			 const char *name, uint32_t id)
{
	struct id_entry *entry;

	if (!name)
		return;
	entry = find_entry(object, kind, name);
	if (!entry)
		return;
	if (entry->id && entry->id != id && verbose)
		message("warning", "multiple BTF IDs for %s: %u and %u, using %u",
			name, entry->id, id, entry->id);
	else if (!entry->id)
		entry->id = id;
}

static int resolve_symbols(struct object *object, const void *data, size_t size)
{
	struct btf_view view;
	size_t offset = 0;
	uint32_t id = 1;

	if (btf_view_init(&view, data, size))
		return -EINVAL;

	while (offset < view.type_size) {
		const struct btf_type *type;
		const char *name;
		uint32_t name_offset;
		uint32_t info;
		uint32_t kind;
		uint32_t vlen;
		size_t record_size;

		if (view.type_size - offset < sizeof(*type)) {
			message("error", "truncated BTF type section");
			return -EINVAL;
		}

		type = (const struct btf_type *)(view.types + offset);
		name_offset = read_le32(&type->name_off);
		info = read_le32(&type->info);
		kind = BTF_INFO_KIND(info);
		vlen = BTF_INFO_VLEN(info);
		if (btf_record_size(kind, vlen, &record_size) ||
		    record_size > view.type_size - offset) {
			message("error", "invalid BTF record %u", id);
			return -EINVAL;
		}

		name = btf_string(&view, name_offset);
		if (kind == BTF_KIND_STRUCT)
			resolve_type(object, ID_STRUCT, name, id);
		else if (kind == BTF_KIND_UNION)
			resolve_type(object, ID_UNION, name, id);
		else if (kind == BTF_KIND_TYPEDEF)
			resolve_type(object, ID_TYPEDEF, name, id);
		else if (kind == BTF_KIND_FUNC)
			resolve_type(object, ID_FUNC, name, id);

		offset += record_size;
		id++;
	}

	if (offset != view.type_size) {
		message("error", "BTF type section has trailing data");
		return -EINVAL;
	}
	return 0;
}

static int compare_ids(const void *left, const void *right)
{
	const uint32_t *a = left;
	const uint32_t *b = right;

	return *a > *b ? 1 : *a < *b ? -1 : 0;
}

static int patch_symbols(struct object *object)
{
	unsigned char *data = object->ids->d_buf;
	size_t i;

	for (i = 0; i < object->entry_count; i++) {
		struct id_entry *entry = &object->entries[i];
		size_t j;

		for (j = 0; j < entry->address_count; j++) {
			size_t offset = (size_t)entry->addresses[j];

			if (offset > object->ids_size - sizeof(uint32_t))
				return -EINVAL;
			write_native32(data + offset, entry->id);
		}

		if (entry->kind == ID_SET) {
			size_t offset = (size_t)entry->addresses[0];
			size_t count = (size_t)(entry->set_size / sizeof(uint32_t)) - 1;
			uint32_t *members;

			if (count > (object->ids_size - offset) / sizeof(uint32_t) - 1)
				return -EINVAL;
			write_native32(data + offset, (uint32_t)count);
			members = (uint32_t *)(data + offset + sizeof(uint32_t));
			qsort(members, count, sizeof(*members), compare_ids);
		}

		if (!entry->id && entry->kind != ID_SET)
			message("warning", "unresolved BTF ID: %s", entry->name);
	}

	object->ids->d_type = ELF_T_WORD;
	if (!elf_flagdata(object->ids, ELF_C_SET, ELF_F_DIRTY)) {
		message("error", "cannot mark %s dirty: %s",
			BTF_IDS_SECTION, elf_errmsg(-1));
		return -EINVAL;
	}
	if (elf_update(object->elf, ELF_C_WRITE) < 0) {
		message("error", "cannot update ELF: %s", elf_errmsg(-1));
		return -EINVAL;
	}
	return 0;
}

static void free_object(struct object *object)
{
	size_t i;

	for (i = 0; i < object->entry_count; i++) {
		free(object->entries[i].name);
		free(object->entries[i].addresses);
	}
	free(object->entries);
	if (object->elf)
		elf_end(object->elf);
	if (object->fd >= 0)
		close(object->fd);
}

static void usage(const char *program)
{
	fprintf(stderr,
		"usage: %s [--btf FILE] [--no-fail] [-v] ELF\\n",
		program);
}

int main(int argc, char **argv)
{
	static const struct option options[] = {
		{ "btf", required_argument, NULL, 'b' },
		{ "no-fail", no_argument, NULL, 'n' },
		{ "verbose", no_argument, NULL, 'v' },
		{ NULL, 0, NULL, 0 },
	};
	struct object object = {
		.fd = -1,
	};
	unsigned char *external_btf = NULL;
	size_t external_btf_size = 0;
	const char *btf_path = NULL;
	int no_fail = 0;
	int option;
	int ret = 1;

	while ((option = getopt_long(argc, argv, "b:nv", options, NULL)) != -1) {
		switch (option) {
		case 'b':
			btf_path = optarg;
			break;
		case 'n':
			no_fail = 1;
			break;
		case 'v':
			verbose++;
			break;
		default:
			usage(argv[0]);
			return 2;
		}
	}
	if (optind != argc - 1) {
		usage(argv[0]);
		return 2;
	}

	object.path = argv[optind];
	if (elf_version(EV_CURRENT) == EV_NONE) {
		message("error", "libelf initialization failed");
		goto out;
	}

	object.fd = open(object.path, O_RDWR);
	if (object.fd < 0) {
		message("error", "cannot open %s: %s",
			object.path, strerror(errno));
		goto out;
	}
	object.elf = elf_begin(object.fd, ELF_C_RDWR, NULL);
	if (!object.elf) {
		message("error", "cannot create ELF descriptor: %s",
			elf_errmsg(-1));
		goto out;
	}
	if (elf_kind(object.elf) != ELF_K_ELF) {
		message("error", "%s is not an ELF file", object.path);
		goto out;
	}
	elf_flagelf(object.elf, ELF_C_SET, ELF_F_LAYOUT);

	if (collect_sections(&object))
		goto out;
	if (!object.ids) {
		if (no_fail) {
			ret = 0;
			goto out;
		}
		message("error", "ELF is missing %s", BTF_IDS_SECTION);
		goto out;
	}
	if (collect_symbols(&object))
		goto out;

	if (btf_path) {
		if (load_file(btf_path, &external_btf, &external_btf_size))
			goto out;
		object.btf = NULL;
	}

	if (!object.btf && !external_btf) {
		if (no_fail) {
			ret = 0;
			goto out;
		}
		message("error", "ELF is missing %s", BTF_SECTION);
		goto out;
	}
	if (resolve_symbols(&object,
			    external_btf ? external_btf : object.btf->d_buf,
			    external_btf ? external_btf_size : object.btf->d_size))
		goto out;
	if (patch_symbols(&object))
		goto out;

	ret = 0;
out:
	free(external_btf);
	free_object(&object);
	return ret;
}
