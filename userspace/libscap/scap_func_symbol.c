/*
 * Copyright (c) 2016 GitHub, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "scap_func_symbol.h"
#include <fcntl.h>
#include <unistd.h>
#include <linux/limits.h>
#include <stdio.h>
#include <libgen.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

// Constants are the integer part of the sines of integers (in radians) * 2^32.
static const uint32_t k[64] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee ,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501 ,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be ,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821 ,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa ,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8 ,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed ,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a ,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c ,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70 ,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05 ,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665 ,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039 ,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1 ,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1 ,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391 };

// r specifies the per-round shift amounts
static const uint32_t r[] = {7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
                      5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
                      4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
                      6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};

// leftrotate function definition
#define LEFTROTATE(x, c) (((x) << (c)) | ((x) >> (32 - (c))))

#define ELF_ST_TYPE(x) (((uint32_t) x) & 0xf)

static int _find_sym(const char *symbol_name, uint64_t addr, void *payload) {
	struct symbol *sym = (struct symbol *)payload;
	if (!strcmp(sym->name, symbol_name)) {
		sym->offset = addr;
		return -1;
	}
	return 0;
}

static int _find_load(uint64_t v_addr, uint64_t mem_sz, uint64_t file_offset,
		      void *payload) {
	struct load_addr_t *addr = (struct load_addr_t *)(payload);
	if (addr->target_addr >= v_addr && addr->target_addr < (v_addr + mem_sz)) {
		addr->binary_addr = addr->target_addr - v_addr + file_offset;
		return -1;
	}
	return 0;
}

// The CRC algorithm used by GNU debuglink. Taken from:
//    https://sourceware.org/gdb/onlinedocs/gdb/Separate-Debug-Files.html
static unsigned int gnu_debuglink_crc32(unsigned int crc,
					char *buf, size_t len) {
	static const unsigned int crc32_table[256] =
		{
			0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419,
			0x706af48f, 0xe963a535, 0x9e6495a3, 0x0edb8832, 0x79dcb8a4,
			0xe0d5e91e, 0x97d2d988, 0x09b64c2b, 0x7eb17cbd, 0xe7b82d07,
			0x90bf1d91, 0x1db71064, 0x6ab020f2, 0xf3b97148, 0x84be41de,
			0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7, 0x136c9856,
			0x646ba8c0, 0xfd62f97a, 0x8a65c9ec, 0x14015c4f, 0x63066cd9,
			0xfa0f3d63, 0x8d080df5, 0x3b6e20c8, 0x4c69105e, 0xd56041e4,
			0xa2677172, 0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b,
			0x35b5a8fa, 0x42b2986c, 0xdbbbc9d6, 0xacbcf940, 0x32d86ce3,
			0x45df5c75, 0xdcd60dcf, 0xabd13d59, 0x26d930ac, 0x51de003a,
			0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423, 0xcfba9599,
			0xb8bda50f, 0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
			0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d, 0x76dc4190,
			0x01db7106, 0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f,
			0x9fbfe4a5, 0xe8b8d433, 0x7807c9a2, 0x0f00f934, 0x9609a88e,
			0xe10e9818, 0x7f6a0dbb, 0x086d3d2d, 0x91646c97, 0xe6635c01,
			0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e, 0x6c0695ed,
			0x1b01a57b, 0x8208f4c1, 0xf50fc457, 0x65b0d9c6, 0x12b7e950,
			0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3,
			0xfbd44c65, 0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2,
			0x4adfa541, 0x3dd895d7, 0xa4d1c46d, 0xd3d6f4fb, 0x4369e96a,
			0x346ed9fc, 0xad678846, 0xda60b8d0, 0x44042d73, 0x33031de5,
			0xaa0a4c5f, 0xdd0d7cc9, 0x5005713c, 0x270241aa, 0xbe0b1010,
			0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
			0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17,
			0x2eb40d81, 0xb7bd5c3b, 0xc0ba6cad, 0xedb88320, 0x9abfb3b6,
			0x03b6e20c, 0x74b1d29a, 0xead54739, 0x9dd277af, 0x04db2615,
			0x73dc1683, 0xe3630b12, 0x94643b84, 0x0d6d6a3e, 0x7a6a5aa8,
			0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1, 0xf00f9344,
			0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb,
			0x196c3671, 0x6e6b06e7, 0xfed41b76, 0x89d32be0, 0x10da7a5a,
			0x67dd4acc, 0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5,
			0xd6d6a3e8, 0xa1d1937e, 0x38d8c2c4, 0x4fdff252, 0xd1bb67f1,
			0xa6bc5767, 0x3fb506dd, 0x48b2364b, 0xd80d2bda, 0xaf0a1b4c,
			0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55, 0x316e8eef,
			0x4669be79, 0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
			0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f, 0xc5ba3bbe,
			0xb2bd0b28, 0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31,
			0x2cd99e8b, 0x5bdeae1d, 0x9b64c2b0, 0xec63f226, 0x756aa39c,
			0x026d930a, 0x9c0906a9, 0xeb0e363f, 0x72076785, 0x05005713,
			0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38, 0x92d28e9b,
			0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21, 0x86d3d2d4, 0xf1d4e242,
			0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1,
			0x18b74777, 0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c,
			0x8f659eff, 0xf862ae69, 0x616bffd3, 0x166ccf45, 0xa00ae278,
			0xd70dd2ee, 0x4e048354, 0x3903b3c2, 0xa7672661, 0xd06016f7,
			0x4969474d, 0x3e6e77db, 0xaed16a4a, 0xd9d65adc, 0x40df0b66,
			0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
			0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605,
			0xcdd70693, 0x54de5729, 0x23d967bf, 0xb3667a2e, 0xc4614ab8,
			0x5d681b02, 0x2a6f2b94, 0xb40bbe37, 0xc30c8ea1, 0x5a05df1b,
			0x2d02ef8d
		};
	char *end;

	crc = ~crc & 0xffffffff;
	for (end = buf + len; buf < end; ++buf)
		crc = crc32_table[(crc ^ *buf) & 0xff] ^ (crc >> 8);
	return ~crc & 0xffffffff;
}

static int verify_checksum(const char *file, unsigned int crc) {
	struct stat st;
	int fd;
	void *buf;
	unsigned int actual;

	fd = open(file, O_RDONLY);
	if (fd < 0)
		return 0;

	if (fstat(fd, &st) < 0) {
		close(fd);
		return 0;
	}

	buf = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (!buf) {
		close(fd);
		return 0;
	}

	actual = gnu_debuglink_crc32(0, buf, st.st_size);

	munmap(buf, st.st_size);
	close(fd);
	return actual == crc;
}

static Elf_Scn * get_section(Elf *e, const char *section_name,
			    GElf_Shdr *section_hdr, size_t *section_idx) {
	Elf_Scn *section = NULL;
	GElf_Shdr header;
	char *name;

	size_t stridx;
	if (elf_getshdrstrndx(e, &stridx) != 0)
		return NULL;

	size_t index;
	for (index = 1; (section = elf_nextscn(e, section)) != 0; index++) {
		if (!gelf_getshdr(section, &header))
			continue;

		name = elf_strptr(e, stridx, header.sh_name);
		if (name && !strcmp(name, section_name)) {
			if (section_hdr)
				*section_hdr = header;
			if (section_idx)
				*section_idx = index;
			return section;
		}
	}

	return NULL;
}

static Elf_Data * get_section_elf_data(Elf *e, const char *section_name) {
	Elf_Scn *section = get_section(e, section_name, NULL, NULL);
	if (section)
		return elf_getdata(section, NULL);
	return NULL;
}

static int find_debuglink(Elf *e, char **debug_file, unsigned int *crc) {
	Elf_Data *data = NULL;

	*debug_file = NULL;
	*crc = 0;

	data = get_section_elf_data(e, ".gnu_debuglink");
	if (!data || data->d_size <= 5)
		return 0;

	*debug_file = (char *)data->d_buf;
	*crc = *(unsigned int*)((char *)data->d_buf + data->d_size - 4);

	return *debug_file ? 1 : 0;
}

// Check if two filenames point to the same file, including hard or soft links.
static bool same_file(char *a, const char *b)
{
	struct stat stat_a, stat_b;

	if (stat(a, &stat_a) || stat(b, &stat_b))
		return false;

	if ((stat_a.st_dev == stat_b.st_dev) &&
	   (stat_a.st_ino == stat_b.st_ino))
		return true;
	else
		return false;
}

static char *find_debug_via_debuglink(Elf *e, const char *binpath,
				      int check_crc) {
	char fullpath[PATH_MAX];
	char *tmppath;
	char *bindir = NULL;
	char *res = NULL;
	unsigned int crc;
	char *name;  // the name of the debuginfo file

	if (!find_debuglink(e, &name, &crc))
		return NULL;

	tmppath = strdup(binpath);
	bindir = dirname(tmppath);

	// Search for the file in 'binpath', but ignore the file we find if it
	// matches the binary itself: the binary will always be probed later on,
	// and it might contain poorer symbols (e.g. stripped or partial symbols)
	// than the external debuginfo that might be available elsewhere.
	snprintf(fullpath, sizeof(fullpath),"%s/%s", bindir, name);
	if (same_file(fullpath, binpath) != true && access(fullpath, F_OK) != -1) {
		res = strdup(fullpath);
		goto DONE;
	}

	// Search for the file in 'binpath'/.debug
	snprintf(fullpath, sizeof(fullpath), "%s/.debug/%s", bindir, name);
	if (access(fullpath, F_OK) != -1) {
		res = strdup(fullpath);
		goto DONE;
	}

	// Search for the file in the global debug directory /usr/lib/debug/'binpath'
	snprintf(fullpath, sizeof(fullpath), "/usr/lib/debug%s/%s", bindir, name);
	if (access(fullpath, F_OK) != -1) {
		res = strdup(fullpath);
		goto DONE;
	}

DONE:
	free(tmppath);
	if (res && check_crc && !verify_checksum(res, crc)) {
		free(res);
		return NULL;
	}
	return res;
}

static int find_buildid(Elf *e, char *buildid) {
	Elf_Data *data = get_section_elf_data(e, ".note.gnu.build-id");
	if (!data || data->d_size <= 16 || strcmp((char *)data->d_buf + 12, "GNU"))
		return 0;

	char *buf = (char *)data->d_buf + 16;
	size_t length = data->d_size - 16;
	size_t i = 0;
	for (i = 0; i < length; ++i) {
		sprintf(buildid + (i * 2), "%02hhx", buf[i]);
	}

	return 1;
}

static char *find_debug_via_buildid(Elf *e) {
	char fullpath[PATH_MAX];
	char buildid[128];  // currently 40 seems to be default, let's be safe

	if (!find_buildid(e, buildid))
		return NULL;

	// Search for the file in the global debug directory with a sub-path:
	//    mm/nnnnnn...nnnn.debug
	// Where mm are the first two characters of the buildid, and nnnn are the
	// rest of the build id, followed by .debug.
	snprintf(fullpath, sizeof(fullpath), "/usr/lib/debug/.build-id/%c%c/%s.debug",
		 buildid[0], buildid[1], buildid + 2);
	if (access(fullpath, F_OK) != -1) {
		return strdup(fullpath);
	}

	return NULL;
}

static int openelf_fd(int fd, Elf **elf_out) {
	if (elf_version(EV_CURRENT) == EV_NONE)
		return -1;

	*elf_out = elf_begin(fd, ELF_C_READ, 0);
	if (*elf_out == NULL)
		return -1;

	return 0;
}


static int openelf(const char *path, Elf **elf_out, int *fd_out) {
	*fd_out = open(path, O_RDONLY);
	if (*fd_out < 0)
		return -1;

	if (openelf_fd(*fd_out, elf_out) == -1) {
		close(*fd_out);
		return -1;
	}

	return 0;
}

static char *find_debug_via_symfs(Elf *e, const char* path) {
	char fullpath[PATH_MAX];
	char buildid[128];
	char symfs_buildid[128];
	int check_build_id;
	char *symfs;
	Elf *symfs_e = NULL;
	int symfs_fd = -1;
	char *result = NULL;

	symfs = getenv("BCC_SYMFS");
	if (!symfs || !*symfs)
		goto out;

	check_build_id = find_buildid(e, buildid);

	int ns_prefix_length = 0;
	sscanf(path, "/proc/%*u/root/%n", &ns_prefix_length);
	path += ns_prefix_length;

	snprintf(fullpath, sizeof(fullpath), "%s/%s", symfs, path);
	if (access(fullpath, F_OK) == -1)
		goto out;

	if (openelf(fullpath, &symfs_e, &symfs_fd) < 0) {
		symfs_e = NULL;
		symfs_fd = -1;
		goto out;
	}

	if (check_build_id) {
		if (!find_buildid(symfs_e, symfs_buildid))
			goto out;

		if (strncmp(buildid, symfs_buildid, sizeof(buildid)))
			goto out;
	}

	result = strdup(fullpath);

out:
	if (symfs_e) {
		elf_end(symfs_e);
	}

	if (symfs_fd != -1) {
		close(symfs_fd);
	}

	return result;
}

static char *find_debug_file(Elf* e, const char* path, int check_crc) {
	char *debug_file = NULL;

	// If there is a separate debuginfo file, try to locate and read it, first
	// using symfs, then using the build-id section, finally using the debuglink
	// section. These rules are what perf and gdb follow.
	// See:
	// - https://github.com/torvalds/linux/blob/v5.2/tools/perf/Documentation/perf-report.txt#L325
	// - https://sourceware.org/gdb/onlinedocs/gdb/Separate-Debug-Files.html
	debug_file = find_debug_via_symfs(e, path);
	if (!debug_file)
		debug_file = find_debug_via_buildid(e);
	if (!debug_file)
		debug_file = find_debug_via_debuglink(e, path, check_crc);

	return debug_file;
}

static int list_in_scn(Elf *e, Elf_Scn *section, size_t stridx, size_t symsize,
		       struct symbol_option *option, elf_symcb callback,
		       void *payload, bool debugfile) {
	Elf_Data *data = NULL;

	while ((data = elf_getdata(section, data)) != 0) {
		size_t i, symcount = data->d_size / symsize;

		if (data->d_size % symsize)
			return -1;

		for (i = 0; i < symcount; ++i) {
			GElf_Sym sym;
			const char *name;

			if (!gelf_getsym(data, (int)i, &sym))
				continue;

			if ((name = elf_strptr(e, stridx, sym.st_name)) == NULL)
				continue;
			if (name[0] == 0)
				continue;

			if (sym.st_value == 0)
				continue;

			uint32_t st_type = ELF_ST_TYPE(sym.st_info);
			if (!(option->use_symbol_type & (1 << st_type)))
				continue;

			int ret;
			ret = callback(name, sym.st_value, payload);
			if (ret < 0)
				return 1;      // signal termination to caller
		}
	}

	return 0;
}

static int listsymbols(Elf *e, elf_symcb callback, void *payload,
		       struct symbol_option *option, bool debugfile) {
	Elf_Scn *section = NULL;

	while ((section = elf_nextscn(e, section)) != 0) {
		GElf_Shdr header;

		if (!gelf_getshdr(section, &header))
			continue;

		if (header.sh_type != SHT_SYMTAB && header.sh_type != SHT_DYNSYM)
			continue;

		int rc = list_in_scn(e, section, header.sh_link, header.sh_entsize,
				     option, callback, payload, debugfile);
		if (rc == 1)
			break;    // callback signaled termination

		if (rc < 0)
			return rc;
	}

	return 0;
}

static int foreach_sym_core(const char *path, elf_symcb callback,
			    struct symbol_option *option, void *payload,
			    int is_debug_file) {
	Elf *e;
	int fd, res;
	char *debug_file;

	if (!option)
		return -1;

	if (openelf(path, &e, &fd) < 0)
		return -1;

	if (option->use_debug_file && !is_debug_file) {
		// The is_debug_file argument helps avoid infinitely resolving debuginfo
		// files for debuginfo files and so on.
		debug_file = find_debug_file(e, path,
					     option->check_debug_file_crc);
		if (debug_file) {
			foreach_sym_core(debug_file, callback, option, payload, 1);
			free(debug_file);
		}
	}

	res = listsymbols(e, callback, payload, option, is_debug_file);
	elf_end(e);
	close(fd);
	return res;
}

int bcc_resolve_symname(const char *module, const char *symbol_name, uint64_t *res_addr) {
	int module_type;

	static struct symbol_option default_option = {
		.use_debug_file = 1,
		.check_debug_file_crc = 1,
		.use_symbol_type = 65535,
	};

	if (module == NULL || symbol_name == NULL)
		return -1;

	struct symbol sym;
	memset(&sym, 0, sizeof(struct symbol));

	sym.module = strdup(module);
	sym.name = symbol_name;

	if (bcc_elf_foreach_sym(module, _find_sym, &default_option, &sym) < 0)
		return -1;
	if (sym.offset == 0x0)
		return -1;

	// For executable (ET_EXEC) binaries and shared objects (ET_DYN), translate
	// the virtual address to physical address in the binary file.
	module_type = bcc_elf_get_type(sym.module);
	if (module_type == ET_EXEC || module_type == ET_DYN) {
		struct load_addr_t addr = {
			.target_addr = sym.offset,
			.binary_addr = 0x0,
		};
		if (bcc_elf_foreach_load_section(sym.module, &_find_load, &addr) < 0)
			return -1;
		if (!addr.binary_addr)
			return -1;
		*res_addr = addr.binary_addr;
	}
	return 0;
}

int bcc_elf_foreach_sym(const char *path, elf_symcb callback,
                        void *option, void *payload) {
	struct symbol_option *o = option;
	return foreach_sym_core(path, callback, o, payload, 0);
}

int bcc_elf_get_type(const char *path) {
	Elf *e;
	GElf_Ehdr hdr;
	int fd;
	void* res = NULL;

	if (openelf(path, &e, &fd) < 0)
		return -1;

	res = (void*)gelf_getehdr(e, &hdr);
	elf_end(e);
	close(fd);

	if (!res)
		return -1;
	else
		return hdr.e_type;
}

int bcc_elf_foreach_load_section(const char *path,
			     elf_load_sectioncb callback,
			     void *payload) {
	Elf *e = NULL;
	int fd = -1, err = -1, res;
	size_t nhdrs, i;

	if (openelf(path, &e, &fd) < 0)
		goto exit;

	if (elf_getphdrnum(e, &nhdrs) != 0)
		goto exit;

	GElf_Phdr header;
	for (i = 0; i < nhdrs; i++) {
		if (!gelf_getphdr(e, (int)i, &header))
			continue;
		if (header.p_type != PT_LOAD || !(header.p_flags & PF_X))
			continue;
		res = callback(header.p_vaddr, header.p_memsz, header.p_offset, payload);
		if (res < 0) {
			err = 1;
			goto exit;
		}
	}
	err = 0;

exit:
	if (e)
		elf_end(e);
	if (fd >= 0)
		close(fd);
	return err;
}

void to_bytes(uint32_t val, uint8_t *bytes)
{
    bytes[0] = (uint8_t) val;
    bytes[1] = (uint8_t) (val >> 8);
    bytes[2] = (uint8_t) (val >> 16);
    bytes[3] = (uint8_t) (val >> 24);
}

uint32_t to_int32(const uint8_t *bytes)
{
    return (uint32_t) bytes[0]
           | ((uint32_t) bytes[1] << 8)
           | ((uint32_t) bytes[2] << 16)
           | ((uint32_t) bytes[3] << 24);
}

void encode(const uint8_t *initial_msg, size_t initial_len, uint8_t *digest) {

    // These vars will contain the hash
    uint32_t h0, h1, h2, h3;

    // Message (to prepare)
    uint8_t *msg = NULL;

    size_t new_len, offset;
    uint32_t w[16];
    uint32_t a, b, c, d, i, f, g, temp;

    // Initialize variables - simple count in nibbles:
    h0 = 0x67452301;
    h1 = 0xefcdab89;
    h2 = 0x98badcfe;
    h3 = 0x10325476;

    //Pre-processing:
    //append "1" bit to message
    //append "0" bits until message length in bits ≡ 448 (mod 512)
    //append length mod (2^64) to message

    for (new_len = initial_len + 1; new_len % (512/8) != 448/8; new_len++)
        ;

    msg = (uint8_t*)malloc(new_len + 8);
    memcpy(msg, initial_msg, initial_len);
    msg[initial_len] = 0x80; // append the "1" bit; most significant bit is "first"
    for (offset = initial_len + 1; offset < new_len; offset++)
        msg[offset] = 0; // append "0" bits

    // append the len in bits at the end of the buffer.
    to_bytes(initial_len*8, msg + new_len);
    // initial_len>>29 == initial_len*8>>32, but avoids overflow.
    to_bytes(initial_len>>29, msg + new_len + 4);

    // Process the message in successive 512-bit chunks:
    //for each 512-bit chunk of message:
    for(offset=0; offset<new_len; offset += (512/8)) {

        // break chunk into sixteen 32-bit words w[j], 0 ≤ j ≤ 15
        for (i = 0; i < 16; i++)
            w[i] = to_int32(msg + offset + i*4);

        // Initialize hash value for this chunk:
        a = h0;
        b = h1;
        c = h2;
        d = h3;

        // Main loop:
        for(i = 0; i<64; i++) {

            if (i < 16) {
                f = (b & c) | ((~b) & d);
                g = i;
            } else if (i < 32) {
                f = (d & b) | ((~d) & c);
                g = (5*i + 1) % 16;
            } else if (i < 48) {
                f = b ^ c ^ d;
                g = (3*i + 5) % 16;
            } else {
                f = c ^ (b | (~d));
                g = (7*i) % 16;
            }

            temp = d;
            d = c;
            c = b;
            b = b + LEFTROTATE((a + f + k[i] + w[g]), r[i]);
            a = temp;

        }

        // Add this chunk's hash to result so far:
        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;

    }

    // cleanup
    free(msg);

    //var char digest[16] := h0 append h1 append h2 append h3 //(Output is in little-endian)
    to_bytes(h0, digest);
    to_bytes(h1, digest + 4);
    to_bytes(h2, digest + 8);
    to_bytes(h3, digest + 12);
}

char* generate_identifier(char *msg){
    size_t len;
    int i;
    uint8_t result[16];
    len = strlen(msg);

    encode((uint8_t*)msg, len, result);

    static char str[35];
    str[0] = '_';
    int j = 0;
    for (i = 0; i < 16; i++){
        j += sprintf( str + 1 + j, "%2.2x",result[i]);
    }
    return str;
}