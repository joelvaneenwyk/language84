//  Unused primitive identifiers
//
//   02  07
//   16
//   22  25
//   34  37
//   44  45  48  49
//   51  57
//   64  65  69
//   70  73  77
//   81  83
//   90  94  96

#define static_assert(c) _Static_assert(c, #c)

typedef unsigned long size_t;

typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef unsigned long uint64_t;

typedef signed char int8_t;
typedef short int int16_t;
typedef int int32_t;
typedef long int64_t;

typedef unsigned long uintptr_t;

typedef _Bool bool;

typedef int pid_t;
typedef unsigned long rlim_t;

struct rlimit {
    rlim_t rlim_cur;
    rlim_t rlim_max;
};

typedef unsigned int mode_t;

typedef long off_t;

typedef unsigned long dev_t;
typedef unsigned long ino_t;
typedef unsigned long nlink_t;
typedef unsigned uid_t;
typedef unsigned gid_t;
typedef long blksize_t;
typedef long blkcnt_t;

typedef long time_t;

struct timespec {
    time_t tv_sec;
    long tv_nsec;
};

struct stat {
    dev_t st_dev;
    ino_t st_ino;
    nlink_t st_nlink;

    mode_t st_mode;
    uid_t st_uid;
    gid_t st_gid;
    unsigned pad1;
    dev_t st_rdev;
    off_t st_size;
    blksize_t st_blksize;
    blkcnt_t st_blocks;

    struct timespec st_atim;
    struct timespec st_mtim;
    struct timespec st_ctim;
    long pad2[3];
};

#define false 0
#define true 1

#define INT8_MIN (-128)
#define INT8_MAX 127

#define INT16_MIN (-32768)
#define INT16_MAX 32767

#define INT32_MIN (-2147483648)
#define INT32_MAX 2147483647

#define INT64_MIN (-9223372036854775807LL - 1)
#define INT64_MAX 9223372036854775807LL

#define UINT8_MAX 255
#define UINT16_MAX 65535
#define UINT32_MAX 4294967295
#define UINT64_MAX (2 * 9223372036854775807ULL + 1)

#define NULL ((void *)0)

#define RLIMIT_STACK 3
#define RLIM_INFINITY -1

#define O_RDONLY 00
#define O_WRONLY 01
#define O_RDWR 02
#define O_CREAT 0100
#define O_TRUNC 01000
#define O_CLOEXEC 02000000

#define PROT_READ 1
#define PROT_WRITE 2
#define PROT_EXEC 4

#define SYS_read 0
#define SYS_write 1
#define SYS_open 2
#define SYS_close 3
#define SYS_stat 4
#define SYS_fstat 5
#define SYS_mmap 9
#define SYS_munmap 11
#define SYS_getpid 39
#define SYS_execve 59
#define SYS_exit 60
#define SYS_getcwd 79
#define SYS_getrlimit 97
#define SYS_setrlimit 160
#define SYS_exit_group 231
#define SYS_epoll_wait 232
#define SYS_epoll_ctl 233
#define SYS_epoll_create1 291

long syscall0(long n);
long syscall1(long n, long a1);
long syscall2(long n, long a1, long a2);
long syscall3(long n, long a1, long a2, long a3);
long syscall4(long n, long a1, long a2, long a3, long a4);
long syscall5(long n, long a1, long a2, long a3, long a4, long a5);
long syscall6(long n, long a1, long a2, long a3, long a4, long a5, long a6);

__asm__(
    ".text\n"
    "syscall0:\n"
    "   mov %rdi, %rax\n"
    "   syscall\n"
    "   retq\n"
    "syscall1:\n"
    "   mov %rdi, %rax\n"
    "   mov %rsi, %rdi\n"
    "   syscall\n"
    "   retq\n"
    "syscall2:\n"
    "   mov %rdi, %rax\n"
    "   mov %rsi, %rdi\n"
    "   mov %rdx, %rsi\n"
    "   syscall\n"
    "   retq\n"
    "syscall3:\n"
    "   mov %rdi, %rax\n"
    "   mov %rsi, %rdi\n"
    "   mov %rdx, %rsi\n"
    "   mov %rcx, %rdx\n"
    "   syscall\n"
    "   retq\n"
    "syscall4:\n"
    "   mov %rdi, %rax\n"
    "   mov %rsi, %rdi\n"
    "   mov %rdx, %rsi\n"
    "   mov %rcx, %rdx\n"
    "   mov %r8, %r10\n"
    "   syscall\n"
    "   retq\n"
    "syscall5:\n"
    "   mov %rdi, %rax\n"
    "   mov %rsi, %rdi\n"
    "   mov %rdx, %rsi\n"
    "   mov %rcx, %rdx\n"
    "   mov %r8, %r10\n"
    "   mov %r9, %r8\n"
    "   syscall\n"
    "   retq\n"
    "syscall6:\n"
    "   mov %rdi, %rax\n"
    "   mov %rsi, %rdi\n"
    "   mov %rdx, %rsi\n"
    "   mov %rcx, %rdx\n"
    "   mov %r8, %r10\n"
    "   mov %r9, %r8\n"
    "   mov 8(%rsp), %r9\n"
    "   syscall\n"
    "   retq\n"
    ".global _start\n"
    "_start:\n"
    "   xor %rbp, %rbp\n"
    "   mov (%rsp), %rdi\n"
    "   lea 8(%rsp), %rsi\n"
    "   call main\n"
    "   mov %rax, %rdi\n"
    "   mov $60, %rax\n"
    "   syscall\n"
);

uint16_t htole16(uint16_t x) { return x; }
uint32_t htole32(uint32_t x) { return x; }
uint64_t htole64(uint64_t x) { return x; }

uint16_t le16toh(uint16_t x) { return x; }
uint32_t le32toh(uint32_t x) { return x; }
uint64_t le64toh(uint64_t x) { return x; }

int
execve(const char *path, const char **argv, const char **env)
{
    return syscall3(SYS_execve, (long)path, (long)argv, (long)env);
}

_Noreturn void
exit(int status)
{
    syscall1(SYS_exit_group, status);
    for (;;) syscall1(SYS_exit, status);
}

int
getcwd(char *buf, size_t size)
{
    return syscall2(SYS_getcwd, (long)buf, size);
}

pid_t
getpid(void)
{
    return syscall0(SYS_getpid);
}

int
getrlimit(int resource, struct rlimit *rlim)
{
    int r = syscall2(SYS_getrlimit, resource, (long)rlim);
    if (r < 0) return -1;
    return 0;
}

int
setrlimit(int resource, const struct rlimit *rlim)
{
    int r = syscall2(SYS_setrlimit, resource, (long)rlim);
    if (r < 0) return -1;
    return 0;
}

int
read(int fd, void *buf, size_t count)
{
    return syscall3(SYS_read, fd, (long)buf, (long)count);
}

int
write(int fd, const void *buf, size_t count)
{
    return syscall3(SYS_write, fd, (long)buf, (long)count);
}

int
close(int fd)
{
    return syscall1(SYS_close, fd);
}

int
open(const char *filename, int flags, mode_t mode)
{
    return syscall3(SYS_open, (long)filename, flags, mode);
}

int
fstat(int fd, struct stat *stat)
{
    return syscall2(SYS_fstat, fd, (long)stat);
}

long
mmap(void *pref, long size, long prot, long flags, long fd, long offset)
{
    return syscall6(SYS_mmap, (long)pref, size, prot, flags, fd, offset);
}

long
munmap(void *bytes, long size)
{
    return syscall2(SYS_munmap, (long)bytes, size);
}

int
epoll_create1(int flags)
{
    return syscall1(SYS_epoll_create1, flags);
}

int
epoll_ctl(int epoll_fd, int op, int fd, void *event)
{
    return syscall4(SYS_epoll_ctl, epoll_fd, op, fd, (long)event);
}

int
epoll_wait(int epoll_fd, void *events, int num_events, int timeout)
{
    return syscall4(SYS_epoll_wait, epoll_fd, (long)events, num_events, timeout);
}

size_t
strlen(const char *s)
{
    size_t size = 0;
    while (s[size] != '\0') ++size;
    return size;
}

void *
memcpy(void *dest, const void *src, size_t n)
{
    char *d = dest;
    const char *s = src;

    if (n > 0 && d != s) for (size_t i = 0; i < n; i++) d[i] = s[i];

    return dest;
}

void *
memmove(void *dest, const void *src, size_t n)
{
    char *d = dest;
    const char *s = src;

    if (n > 0 && d != s) {
        if (s < d && d < s + n)
            for (size_t i = 1; i <= n; i++) d[n - i] = s[n - i];
        else
            for (size_t i = 0; i < n; i++) d[i] = s[i];
    }

    return dest;
}

void *
memset(void *dest, int c, size_t n)
{
    char *d = dest;
    for (size_t i = 0; i < n; i++) d[i] = c;
    return dest;
}

typedef uint32_t value;

static_assert(_Alignof(value) <= 4);

struct closure {
    void *native_code;
    uint16_t num_params;
    uint16_t env_size;
    value env_items[];
};

struct tuple {
    uint16_t num_items;
    uint16_t layout;
    value items[];
};

struct variant {
    uint16_t label;
    value item;
};

#define CHUNK_NUM_BYTES_MAX 0x3fffffff

#define CHUNK_RO 1
#define CHUNK_RW 2

struct chunk {
    uint32_t header;
    char bytes[];
};

static_assert(_Alignof(struct closure) <= 8);
static_assert(_Alignof(struct tuple) <= 4);
static_assert(_Alignof(struct variant) <= 4);
static_assert(_Alignof(struct chunk) <= 4);

#define TAG_HEAP_CLOSURE 0x1
#define TAG_HEAP_TUPLE 0x3
#define TAG_HEAP_VARIANT 0x5
#define TAG_HEAP_CHUNK 0x7
#define TAG_IMMEDIATE_BOOLEAN 0x0f
#define TAG_IMMEDIATE_TUPLE 0x1f
#define TAG_IMMEDIATE_VARIANT 0x2f
#define TAG_IMMEDIATE_CHUNK 0x3f

#define empty_tuple TAG_IMMEDIATE_TUPLE

#define value_true TAG_IMMEDIATE_BOOLEAN
#define value_false (TAG_IMMEDIATE_BOOLEAN | 0x100)

#define INTEGER_MIN (INT32_MIN / 2)
#define INTEGER_MAX (INT32_MAX / 2)

static_assert(CHUNK_NUM_BYTES_MAX <= INTEGER_MAX);

static struct {
    uint32_t num_entries;
    const uint16_t *entries;
} record_layouts;

#define NUM_MEMORY_MAPPINGS 16

static struct {
    void *bytes;
    size_t size;
    int prot;
} memory_mappings[NUM_MEMORY_MAPPINGS];

static int command_argc;
static const char **command_argv;

static void
err_print_line(const char *s)
{
    write(2, s, strlen(s));
    write(2, "\n", 1);
}

static _Noreturn void
halt(void)
{
    exit(1);
}

static _Noreturn void
die(const char *s)
{
    err_print_line(s);
    halt();
}

//  The Heap
//
//  The heap is a single contiguous memory region in which value
//  representation data is stored.
//
//  The heap grows monotonically. If its capacity is exceeded, then the
//  process exits with a nonzero exit status.
//
//  The size of the heap for a given program is fixed at compile time and
//  is at most pow(2, 30) bytes (1 GiB).
//
//  All objects allocated in the heap have 4-byte, 8-byte, or 16-byte
//  alignment. Each object allocated in the heap has an associated heap
//  identifier, established by heap_alloc. The heap_access function provides
//  the means for obtaining the native address of an object with a given heap
//  identifier.
//
//  Members:
//      bytes - The bytes member holds the native address of the memory
//          region, which must have 16-byte alignment. The memory region
//          starting at this address must contain at least (4 * heap.limit)
//          bytes.
//      limit - The limit member establishes the growth limit for the heap. It
//          must not exceed pow(2, 28). The capacity of the heap is
//          (4 * heap.limit) bytes. This limit is fixed at initialization
//          time.
//      top - The top member grows as allocations are made but never exceeds
//          the limit member. It is initially zero.

static struct {
    char *bytes;
    uint32_t limit;
    uint32_t top;
} heap;

//  heap_access
//
//  Parameters:
//      id - A heap object identifier produced by heap_alloc.

static void *
heap_access(uint32_t id)
{
    return heap.bytes + 4 * id;
}

//  heap_alloc
//
//  Parameters:
//      align - The address alignment constraint. It must be 1, 2, 4, 8, or 16.
//      size - The number of bytes required, which must be greater than zero.

static uint32_t
heap_alloc(int align, size_t size)
{
    uint32_t c = (align - 1) / 4;
    uint32_t id = (heap.top + c) & ~c;
    if (id > heap.limit || size > 4 * (heap.limit - id))
        die("Failed to allocate memory.");
    heap.top = id + (size + 3) / 4;
    return id;
}

static value
value_make_box(unsigned int tag, uint32_t id)
{
    return (id << 4) | tag;
}

static void *
value_unbox(value x)
{
    return heap_access(x >> 4);
}

static bool
value_has_tag(value x, unsigned int mask, unsigned int tag)
{
    return (x & mask) == tag;
}

static struct closure *
closure_unbox(value closure)
{
    if (!value_has_tag(closure, 0xf, TAG_HEAP_CLOSURE))
        die("Value is not a function.");
    return value_unbox(closure);
}

static struct tuple *
tuple_unbox(value tuple)
{
    if (!value_has_tag(tuple, 0xf, TAG_HEAP_TUPLE))
        die("Value is not a tuple.");
    return value_unbox(tuple);
}

static struct variant *
variant_unbox(value variant)
{
    if (!value_has_tag(variant, 0xf, TAG_HEAP_VARIANT))
        die("Value is not a variant.");
    return value_unbox(variant);
}

static bool
value_is_number(value v)
{
    return (v & 1) == 0;
}

static value
integer_encode(int32_t n)
{
    if (n < INTEGER_MIN || INTEGER_MAX < n)
        die("Number is out of range.");
    return n << 1;
}

static int32_t
integer_decode(value v)
{
    if (!value_is_number(v))
        die("Value is not a number.");
#ifdef __GNUC__
    int32_t n = v; // "implementation-defined" behaviour, according to C11.
    return n >> 1; // "implementation-defined" behaviour, according to C11.
#else
#error "Need validation of implementation-defined behaviour."
#endif
}

static value
boolean_encode(bool b)
{
    return b ? value_true : value_false;
}

static int
global_chunk_decode(value chunk)
{
    if (!value_has_tag(chunk, 0xff, TAG_IMMEDIATE_CHUNK))
        die("Value is not a global chunk.");
    return chunk >> 8;
}

static value
global_chunk_encode(int i)
{
    return (i << 8) | TAG_IMMEDIATE_CHUNK;
}

static uint32_t
chunk_header(int perm, uint32_t num_bytes)
{
    return ((perm == CHUNK_RW) ? 0x80000000 : 0) | num_bytes;
}

static int
chunk_perm(const struct chunk *chunk)
{
    return (chunk->header & 0x80000000) ? CHUNK_RW : CHUNK_RO;
}

static uint32_t
chunk_num_bytes(const struct chunk *chunk)
{
    return (chunk->header & 0x7fffffff);
}

static struct chunk *
chunk_unbox(value chunk)
{
    if (!value_has_tag(chunk, 0xf, TAG_HEAP_CHUNK))
        die("Value is not a chunk.");
    return value_unbox(chunk);
}

static void *
chunk_access(value chunk, int perm, value i_value, unsigned num_bytes)
{
    int64_t i = integer_decode(i_value);
    if (value_has_tag(chunk, 0xf, TAG_HEAP_CHUNK)) {
        struct chunk *chunk_rep = chunk_unbox(chunk);
        if (i < 0 || chunk_num_bytes(chunk_rep) < i + num_bytes)
            die("Chunk access is out of bounds.");
        if (perm == CHUNK_RW && chunk_perm(chunk_rep) == CHUNK_RO)
            die("Chunk is read-only.");
        return &chunk_rep->bytes[i];
    } else if (value_has_tag(chunk, 0xff, TAG_IMMEDIATE_CHUNK)) {
        int j = global_chunk_decode(chunk);
        if (memory_mappings[j].bytes == NULL)
            die("Global chunk is not mapped.");
        if (i < 0 || memory_mappings[j].size < i + num_bytes)
            die("Chunk access is out of bounds.");
        if (perm == CHUNK_RW && !(memory_mappings[j].prot & PROT_WRITE))
            die("Chunk is read-only.");
        return memory_mappings[j].bytes + i;
    }
    die("Value is not a chunk.");
}

static value
string_make(uint32_t num_bytes, const char *bytes)
{
    if (CHUNK_NUM_BYTES_MAX < num_bytes)
        die("String is too big.");
    size_t align = _Alignof(struct chunk);
    size_t size = sizeof(struct chunk) + num_bytes;
    uint32_t id = heap_alloc(align, size);
    struct chunk *chunk_rep = heap_access(id);
    chunk_rep->header = chunk_header(CHUNK_RO, num_bytes);
    if (bytes != NULL)
        memmove(chunk_rep->bytes, bytes, num_bytes);
    return value_make_box(TAG_HEAP_CHUNK, id);
}

static struct chunk *
string_unbox(value string)
{
    if (!value_has_tag(string, 0xf, TAG_HEAP_CHUNK))
        die("Value is not a string.");
    if (chunk_perm(chunk_unbox(string)) != CHUNK_RO)
        die("Value is not a string.");
    return value_unbox(string);
}

static char *
string_bytes(value string)
{
    return string_unbox(string)->bytes;
}

static uint32_t
string_length(value string)
{
    return chunk_num_bytes(string_unbox(string));
}

static const char *
zero_terminated(value s)
{
    uint32_t len = string_length(s);
    char *z = heap_access(heap_alloc(1, len + 1));
    memmove(z, string_bytes(s), len);
    z[len] = '\0';
    return z;
}

#ifdef __GNUC__

//  Implementation-defined behaviour, according to C11.

static int8_t
from_uint8(uint8_t u)
{
    return (int8_t)u;
}

static int16_t
from_uint16(uint16_t u)
{
    return (int16_t)u;
}

static int32_t
from_uint32(uint32_t u)
{
    return (int32_t)u;
}

static int64_t
from_uint64(uint64_t u)
{
    return (int64_t)u;
}

#else
#error "Need validation of implementation-defined behaviour."
#endif

static void
store_uint8(void *bytes, uint8_t u)
{
    memmove(bytes, &u, 1);
}

static void
store_uint16_le(void *bytes, uint16_t u)
{
    u = htole16(u);
    memmove(bytes, &u, 2);
}

static void
store_uint32_le(void *bytes, uint32_t u)
{
    u = htole32(u);
    memmove(bytes, &u, 4);
}

static void
store_uint64_le(void *bytes, uint64_t u)
{
    u = htole64(u);
    memmove(bytes, &u, 8);
}

static void
store_int8(void *bytes, int8_t s)
{
    uint8_t u = s;
    memmove(bytes, &u, 1);
}

static void
store_int16_le(void *bytes, int16_t s)
{
    uint16_t u = s;
    u = htole16(u);
    memmove(bytes, &u, 2);
}

static void
store_int32_le(void *bytes, int32_t s)
{
    uint32_t u = s;
    u = htole32(u);
    memmove(bytes, &u, 4);
}

static void
store_int64_le(void *bytes, int64_t s)
{
    uint64_t u = s;
    u = htole64(u);
    memmove(bytes, &u, 8);
}

static uint8_t
fetch_uint8(const void *bytes)
{
    uint8_t u;
    memmove(&u, bytes, 1);
    return u;
}

static uint16_t
fetch_uint16_le(const void *bytes)
{
    uint16_t u;
    memmove(&u, bytes, 2);
    return le16toh(u);
}

static uint32_t
fetch_uint32_le(const void *bytes)
{
    uint32_t u;
    memmove(&u, bytes, 4);
    return le32toh(u);
}

static uint64_t
fetch_uint64_le(const void *bytes)
{
    uint64_t u;
    memmove(&u, bytes, 8);
    return le64toh(u);
}

static int8_t
fetch_int8(const void *bytes)
{
    uint8_t u;
    memmove(&u, bytes, 1);
    return from_uint8(u);
}

static int16_t
fetch_int16_le(const void *bytes)
{
    uint16_t u;
    memmove(&u, bytes, 2);
    u = le16toh(u);
    return from_uint16(u);
}

static int32_t
fetch_int32_le(const void *bytes)
{
    uint32_t u;
    memmove(&u, bytes, 4);
    u = le32toh(u);
    return from_uint32(u);
}

static int64_t
fetch_int64_le(const void *bytes)
{
    uint64_t u;
    memmove(&u, bytes, 8);
    u = le64toh(u);
    return from_uint64(u);
}

static void
stack_init(uint32_t limit)
{
    const char *error_message = "Failed to set the stack limit.";
    struct rlimit rlim;
    int r = getrlimit(RLIMIT_STACK, &rlim);
    if (r != 0)
        die(error_message);
    rlim.rlim_cur = limit;
    r = setrlimit(RLIMIT_STACK, &rlim);
    if (r != 0)
        die(error_message);
    return;
}

//  s36: init
//
//  heap_num_bytes must be at most pow(2, 30).
//  The alignment of heap_bytes must be at least 16.

void
s36(uint32_t heap_num_bytes, char *heap_bytes, uint32_t stack_limit,
        uint32_t record_layouts_num_entries,
        const uint16_t *record_layouts_entries,
        int argc, const char **argv)
{
    heap.limit = heap_num_bytes / 4;
    heap.top = 0;
    heap.bytes = heap_bytes;
    stack_init(stack_limit);
    record_layouts.num_entries = record_layouts_num_entries;
    record_layouts.entries = record_layouts_entries;
    for (int i = 0; i < NUM_MEMORY_MAPPINGS; i++) {
        memory_mappings[i].bytes = NULL;
        memory_mappings[i].size = 0;
        memory_mappings[i].prot = 0;
    }
    command_argc = argc;
    command_argv = argv;
}

//  s40: prim_command_argc

value
s40(void)
{
    return integer_encode(command_argc);
}

//  s24: prim_command_argv

value
s24(value i_value)
{
    int32_t i = integer_decode(i_value);
    if (i < 0 || i >= command_argc)
        die("Command argument index is out of range.");
    return string_make(strlen(command_argv[i]), command_argv[i]);
}

//  s87: halt
//
//  Halt execution, returing 1 as the exit code of the process.

_Noreturn value
s87(void)
{
    exit(1);
}

//  s52: heap_get_top

uint32_t
s52(void)
{
    return heap.top;
}

//  s15: heap_set_top

void
s15(uint32_t top)
{
    heap.top = top;
}

//  s75: closure_make
//
//  Construct a fresh closure value.
//
//  Parameters:
//      native_code - A C function pointer to a function whose return type is
//          value and which takes one more than num_params arguments, all of
//          type value.
//      num_params - The number of parameters associated with the closure (not
//          the native function).
//      env_size - The number of values to be stored in the closure
//          environment.
//      env_items - If env_size is zero, then env_items may be NULL;
//          otherwise, env_items must be an array containing env_size values.
//          The values provided comprise the environment of the closure.

value
s75(void *native_code, uint16_t num_params, uint16_t env_size,
        const value *env_items)
{
    size_t align = _Alignof(struct closure);
    size_t size = sizeof(struct closure) + env_size * sizeof(value);
    uint32_t id = heap_alloc(align, size);
    struct closure *closure_rep = heap_access(id);
    closure_rep->native_code = native_code;
    closure_rep->num_params = num_params;
    closure_rep->env_size = env_size;
    if (env_size > 0)
        memmove(closure_rep->env_items, env_items, env_size * sizeof(value));
    return value_make_box(TAG_HEAP_CLOSURE, id);
}

//  s62: closure_env_items

const value *
s62(value closure)
{
    const struct closure *closure_rep = closure_unbox(closure);
    return closure_rep->env_items;
}

const void *s35(value closure, uint16_t num_args);
value s78(uint16_t num_items, const value *items);
const value * s33(value tuple, uint16_t num_items);

static value
adapt_closure_1_0(value closure)
{
    return ((value (*)(value, value))s35(closure, 1))(closure, empty_tuple);
}

static value
adapt_closure_1_2(value closure, value x0, value x1)
{
    value x = s78(2, (const value[]){x0, x1});
    return ((value (*)(value, value))s35(closure, 1))(closure, x);
}

static value
adapt_closure_1_3(value closure, value x0, value x1, value x2)
{
    value x = s78(3, (const value[]){x0, x1, x2});
    return ((value (*)(value, value))s35(closure, 1))(closure, x);
}

static value
adapt_closure_1_4(value closure, value x0, value x1, value x2, value x3)
{
    value x = s78(4, (const value[]){x0, x1, x2, x3});
    return ((value (*)(value, value))s35(closure, 1))(closure, x);
}

static value
adapt_closure_0_1(value closure, value x)
{
    if (x != empty_tuple)
        die("Ill-formed function application.");
    return ((value (*)(value))s35(closure, 0))(closure);
}

static value
adapt_closure_2_1(value closure, value x)
{
    const value *items = s33(x, 2);
    value (*f)(value, value, value) = s35(closure, 2);
    return f(closure, items[0], items[1]);
}

static value
adapt_closure_3_1(value closure, value x)
{
    const value *items = s33(x, 3);
    value (*f)(value, value, value, value) = s35(closure, 3);
    return f(closure, items[0], items[1], items[2]);
}

static value
adapt_closure_4_1(value closure, value x)
{
    const value *items = s33(x, 4);
    value (*f)(value, value, value, value, value) = s35(closure, 4);
    return f(closure, items[0], items[1], items[2], items[3]);
}

//  s35: closure_native_code

const void *
s35(value closure, uint16_t num_args)
{
    const struct closure *closure_rep = closure_unbox(closure);
    if (closure_rep->num_params == num_args)
        return closure_rep->native_code;
    if (closure_rep->num_params == 1) {
        switch (num_args) {
        case 0: return adapt_closure_1_0;
        case 2: return adapt_closure_1_2;
        case 3: return adapt_closure_1_3;
        case 4: return adapt_closure_1_4;
        default: die("Limitation: Missing adaptor for function application.");
        }
    }
    if (num_args == 1) {
        switch (closure_rep->num_params) {
        case 0: return adapt_closure_0_1;
        case 2: return adapt_closure_2_1;
        case 3: return adapt_closure_3_1;
        case 4: return adapt_closure_4_1;
        default: die("Limitation: Missing adaptor for function application.");
        }
    }
    die("Ill-formed function application.");
}

//  s27: variant_make_nonempty
//
//  Construct a fresh variant value where the enclosed value is not {}.
//
//  Parameters:
//      label - The label!
//      item - The enclosed value.

value
s27(uint16_t label, value item)
{
    size_t align = _Alignof(struct variant);
    size_t size = sizeof(struct variant);
    uint32_t id = heap_alloc(align, size);
    struct variant *variant_rep = heap_access(id);
    variant_rep->label = label;
    variant_rep->item = item;
    return value_make_box(TAG_HEAP_VARIANT, id);
}

//  s09: variant_label
//
//  The label of a variant value.
//
//  Parameters:
//      variant - The variant!

uint16_t
s09(value variant)
{
    if (value_has_tag(variant, 0xff, TAG_IMMEDIATE_VARIANT))
        return variant >> 8;
    struct variant *variant_rep = variant_unbox(variant);
    return variant_rep->label;
}

//  s06: variant_item
//
//  The value embedded within a variant.
//
//  Parameters:
//      variant - The variant!

value
s06(value variant)
{
    if (value_has_tag(variant, 0xff, TAG_IMMEDIATE_VARIANT))
        return empty_tuple;
    struct variant *variant_rep = variant_unbox(variant);
    return variant_rep->item;
}

//  s30: tuple_make_with_layout

value
s30(uint16_t num_items, const value *items, uint16_t layout)
{
    size_t align = _Alignof(struct tuple);
    size_t size = sizeof(struct tuple) + num_items * sizeof(value);
    uint32_t id = heap_alloc(align, size);
    struct tuple *tuple_rep = heap_access(id);
    tuple_rep->num_items = num_items;
    tuple_rep->layout = layout;
    if (num_items > 0)
        memmove(tuple_rep->items, items, num_items * sizeof(value));
    return value_make_box(TAG_HEAP_TUPLE, id);
}

//  s78: tuple_make_with_no_layout

value
s78(uint16_t num_items, const value *items)
{
    return s30(num_items, items, UINT16_MAX);
}

//  s68: tuple_fetch_at_offset

value
s68(value tuple, uint16_t offset)
{
    const char *error_message = "Ill-formed tuple access.";
    if (tuple == empty_tuple)
        die(error_message);
    struct tuple *tuple_rep = tuple_unbox(tuple);
    if (offset >= tuple_rep->num_items)
        die(error_message);
    return tuple_rep->items[offset];
}

//  s31: tuple_fetch_at_label

value
s31(value tuple, uint16_t label)
{
    const char *error_message = "Ill-formed record access.";
    if (tuple == empty_tuple)
        die(error_message);
    const unsigned short *entries = record_layouts.entries;
    struct tuple *tuple_rep = tuple_unbox(tuple);
    unsigned int layout = tuple_rep->layout;
    if (layout == UINT16_MAX)
        die(error_message);
    for (unsigned int i = layout; entries[i] != UINT16_MAX; i++) {
        if (entries[i] == label)
            return tuple_rep->items[i - layout];
    }
    die(error_message);
}

//  s33: tuple_items

const value *
s33(value tuple, uint16_t num_items)
{
    if (tuple == empty_tuple)
        die("Invalid use of empty tuple.");
    struct tuple *tuple_rep = tuple_unbox(tuple);
    if (tuple_rep->num_items != num_items)
        die("Tuple mismatch.");
    return tuple_rep->items;
}

//  s86: string_make

value
s86(size_t num_bytes, const char *bytes)
{
    return string_make(num_bytes, bytes);
}

//  s89: stuck_cond

_Noreturn value
s89(void)
{
    die("Cond expression has no applicable clause.");
}

//  s88: stuck_switch

_Noreturn value
s88(void)
{
    die("Switch expression has no applicable clause.");
}

//  s53: stuck_match

_Noreturn value
s53(void)
{
    die("Match expression has no applicable clause.");
}

//  s26: prim_die

value
s26(value string)
{
    die(zero_terminated(string));
}

//  s00: prim_exec

static const char *
verified_exec_string(const struct chunk *table, size_t offset)
{
    uint32_t table_size = chunk_num_bytes(table);
    bool found_zero = false;
    for (size_t i = offset; i < table_size; i++) {
        if (table->bytes[i] == 0) {
            found_zero = true;
            break;
        }
    }
    if (!found_zero)
        die("Invalid argument for exec.");
    return &table->bytes[offset];
}

value
s00(value path_offset_value, value arg_offsets_value, value var_offsets_value,
        value table_value)
{
    int32_t path_offset = integer_decode(path_offset_value);
    if (path_offset < 0)
        die("Invalid argument for exec.");
    const struct chunk *arg_offsets = chunk_unbox(arg_offsets_value);
    const struct chunk *var_offsets = chunk_unbox(var_offsets_value);
    const struct chunk *table = chunk_unbox(table_value);
    uint32_t num_args = chunk_num_bytes(arg_offsets) / 4;
    uint32_t num_vars = chunk_num_bytes(var_offsets) / 4;
    size_t args_align = _Alignof(const char *);
    size_t args_size = sizeof(const char *) * (num_args + 1);
    size_t vars_align = _Alignof(const char *);
    size_t vars_size = sizeof(const char *) * (num_vars + 1);
    int r;
    {
        uint32_t top = heap.top;
        const char *path = verified_exec_string(table, path_offset);
        const char **args = heap_access(heap_alloc(args_align, args_size));
        const char **vars = heap_access(heap_alloc(vars_align, vars_size));
        for (uint32_t i = 0; i < num_args; i++) {
            void *offset_bytes =
                chunk_access(arg_offsets_value, CHUNK_RO, integer_encode(4 * i), 4);
            uint32_t offset = fetch_uint32_le(offset_bytes);
            args[i] = verified_exec_string(table, offset);
        }
        args[num_args] = NULL;
        for (uint32_t i = 0; i < num_vars; i++) {
            void *offset_bytes =
                chunk_access(var_offsets_value, CHUNK_RO, integer_encode(4 * i), 4);
            uint32_t offset = fetch_uint32_le(offset_bytes);
            vars[i] = verified_exec_string(table, offset);
        }
        vars[num_vars] = NULL;
        r = execve(path, args, vars);
        heap.top = top;
    }
    return r;
}

//  s05: prim_exit

value
s05(value status_value)
{
    int32_t status = integer_decode(status_value);
    exit(status);
}

//  s85: prim_getcwd

value
s85(void)
{
    //  TODO How to better handle the heap allocation trick used here? (We are
    //  writing into the unallocated region of the heap and subsequently
    //  incorporating the written bytes into the most recently allocated
    //  chunk.)

    size_t align = _Alignof(struct chunk);
    size_t size = sizeof(struct chunk);
    uint32_t id = heap_alloc(align, size);
    struct chunk *chunk_rep = heap_access(id);
    int r = getcwd(chunk_rep->bytes, heap.limit - heap.top);
    if (r < 0)
        die("Failed to get current working directory.");
    size_t pathlen = strlen(chunk_rep->bytes);
    if (pathlen > CHUNK_NUM_BYTES_MAX)
        die("Current working directory path is too long.");
    heap.top += pathlen;
    chunk_rep->header = chunk_header(CHUNK_RO, pathlen);
    return value_make_box(TAG_HEAP_CHUNK, id);
}

//  s66: prim_getpid

value
s66(void)
{
    return integer_encode(getpid());
}

//  s03: prim_open

value
s03(value name, value flags_value, value mode_value)
{
    int32_t flags = integer_decode(flags_value);
    int32_t mode = integer_decode(mode_value);
    int r;
    {
        uint32_t top = heap.top;
        const char *zero_name = zero_terminated(name);
        r = open(zero_name, flags, mode);
        heap.top = top;
    }
    return integer_encode(r);
}

//  s72: prim_close

value
s72(value fd_value)
{
    int32_t fd = integer_decode(fd_value);
    int r = close(fd);
    return integer_encode(r);
}

//  s67: prim_read

value
s67(value fd_value, value chunk, value start_value, value count_value)
{
    int32_t fd = integer_decode(fd_value);
    int32_t count = integer_decode(count_value);
    void *buf = chunk_access(chunk, CHUNK_RW, start_value, count);
    long r = read(fd, buf, count);
    return integer_encode(r);
}

//  s41: prim_write

value
s41(value fd_value, value chunk, value start_value, value count_value)
{
    int32_t fd = integer_decode(fd_value);
    int32_t count = integer_decode(count_value);
    const void *buf = chunk_access(chunk, CHUNK_RO, start_value, count);
    long r = write(fd, buf, count);
    return integer_encode(r);
}

//  s18: prim_print

value
s18(value string)
{
    const char *s = string_bytes(string);
    int r = write(1, s, string_length(string));
    if (r < 0)
        die("Failed to print string.");
    return empty_tuple;
}

//  s79: prim_print_line

value
s79(value string)
{
    //  TODO    Implement this function without using two system calls.
    const char *s = string_bytes(string);
    int r = write(1, s, string_length(string));
    if (r < 0)
        die("Failed to print string.");
    r = write(1, "\n", 1);
    if (r < 0)
        die("Failed to print string.");
    return empty_tuple;
}

//  s20: prim_file_create

value
s20(value name)
{
    int fd;
    {
        uint32_t top = heap.top;
        const char *zero_name = zero_terminated(name);
        int r = open(zero_name, O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC, 0644);
        if (r < 0)
            die("Failed to create file.");
        fd = r;
        heap.top = top;
    }
    return integer_encode(fd);
}

//  s23: prim_file_open

value
s23(value name)
{
    int fd;
    {
        uint32_t top = heap.top;
        const char *zero_name = zero_terminated(name);
        int r = open(zero_name, O_RDONLY|O_CLOEXEC, 0);
        if (r < 0)
            die("Failed to open file.");
        fd = r;
        heap.top = top;
    }
    return integer_encode(fd);
}

//  s92: prim_file_close

value
s92(value fd_value)
{
    int32_t fd = integer_decode(fd_value);
    if (fd <= 2)
        die("Attempted to close stdin, stdout, or stderr.");
    int r = close(fd);
    if (r < 0)
        die("Failed to close file.");
    return empty_tuple;
}

//  s28: prim_file_read_all

value
s28(value fd_value)
{
    int fd = integer_decode(fd_value);
    struct stat statbuf;
    int r = fstat(fd, &statbuf);
    if (r < 0)
        die("Failed to determine file size.");
    off_t file_size = statbuf.st_size;
    if (file_size < 0 || file_size > UINT32_MAX - 1)
        die("Failed to read file.");
    value string = string_make(file_size, NULL);
    char *bytes = string_bytes(string);
    r = read(fd, bytes, file_size);
    if (r != file_size)
        die("Failed to read file.");
    return string;
}

//  s12: prim_show_integer

value
s12(value integer)
{
    int32_t n = integer_decode(integer);
    bool is_negative = (n < 0);
    int32_t m = is_negative ? -n : n;
    char text[16];
    int i = 16;
    if (n == 0) {
        --i;
        text[i] = '0';
    } else {
        while (m > 0) {
            --i;
            text[i] = '0' + (m % 10);
            m /= 10;
        }
        if (is_negative) {
            --i;
            text[i] = '-';
        }
    }
    size_t len = 16 - i;
    return string_make(len, &text[i]);
}

//  s93: prim_multiply

value
s93(value a, value b)
{
    int32_t n;
    if (__builtin_mul_overflow(integer_decode(a), integer_decode(b), &n))
        die("Integer is out of range.");
    return integer_encode(n);
}

//  s19: prim_add

value
s19(value a, value b)
{
    int32_t n;
    if (__builtin_add_overflow(integer_decode(a), integer_decode(b), &n))
        die("Integer is out of range.");
    return integer_encode(n);
}

//  s47: prim_subtract

value
s47(value a, value b)
{
    int32_t n;
    if (__builtin_sub_overflow(integer_decode(a), integer_decode(b), &n))
        die("Integer is out of range.");
    return integer_encode(n);
}

//  s84: prim_negate

value
s84(value n)
{
    if (n == (1 << 31))
        die("Integer is out of range.");
    return integer_encode(-integer_decode(n));
}

struct division_result {
    int32_t q;
    int32_t r;
};

static struct division_result
divide(int32_t b, int32_t a)
{
    if (a == 0)
        die("Division by zero.");

    int32_t b_abs = (b < 0) ? -b : b;
    int32_t a_abs = (a < 0) ? -a : a;

    int32_t q = b_abs / a_abs;
    int32_t r = b_abs % a_abs;

    //  Invariant: b_abs = q * a_abs + r
    //  Invariant: 0 <= r < |a|

    if (b < 0) {
        if (r > 0) {
            q++;
            r -= a_abs;
        }
        q = -q;
        r = -r;
    }

    //  Invariant: b = q * a_abs + r
    //  Invariant: 0 <= r < |a|

    if (a < 0)
        q = -q;

    //  Invariant: b = q * a + r
    //  Invariant: 0 <= r < |a|

    return (struct division_result){.q = q, .r = r};
}

//  s91: prim_quotient

value
s91(value b_value, value a_value)
{
    int32_t b = integer_decode(b_value);
    int32_t a = integer_decode(a_value);
    struct division_result d = divide(b, a);
    return integer_encode(d.q);
}

//  s43: prim_remainder

value
s43(value b_value, value a_value)
{
    int32_t b = integer_decode(b_value);
    int32_t a = integer_decode(a_value);
    struct division_result d = divide(b, a);
    return integer_encode(d.r);
}

//  s50: prim_equal

value
s50(value a, value b)
{
    return boolean_encode(integer_decode(a) == integer_decode(b));
}

//  s10: prim_less

value
s10(value a, value b)
{
    return boolean_encode(integer_decode(a) < integer_decode(b));
}

//  s63: prim_less_or_equal

value
s63(value a, value b)
{
    return boolean_encode(integer_decode(a) <= integer_decode(b));
}

//  s61: prim_greater

value
s61(value a, value b)
{
    return boolean_encode(integer_decode(a) > integer_decode(b));
}

//  s55: prim_greater_or_equal

value
s55(value a, value b)
{
    return boolean_encode(integer_decode(a) >= integer_decode(b));
}

//  s95: prim_memory_map

value
s95(value i_value, value size_value, value prot_value, value flags_value,
        value fd_value, value offset_value)
{
    int32_t i = integer_decode(i_value);
    int32_t size = integer_decode(size_value);
    int32_t prot = integer_decode(prot_value);
    int32_t flags = integer_decode(flags_value);
    int32_t fd = integer_decode(fd_value);
    int32_t offset = integer_decode(offset_value);
    if (i < 0 || NUM_MEMORY_MAPPINGS <= i)
        die("Memory mapping index is out of range.");
    if (memory_mappings[i].bytes != NULL)
        die("Memory mapping is already in use.");
    long r = mmap(NULL, size, prot, flags, fd, offset);
    if (r < 0)
        die("Failed to create memory mapping.");
    memory_mappings[i].bytes = (void *)r;
    memory_mappings[i].size = size;
    memory_mappings[i].prot = prot;
    return empty_tuple;
}

//  s56: prim_memory_unmap

value
s56(value i_value)
{
    int32_t i = integer_decode(i_value);
    if (i < 0 || NUM_MEMORY_MAPPINGS <= i)
        die("Memory mapping index is out of range.");
    if (memory_mappings[i].bytes == NULL)
        return empty_tuple;
    long r = munmap(memory_mappings[i].bytes, memory_mappings[i].size);
    if (r < 0)
        die("Failed to unmap memory mapping.");
    memory_mappings[i].bytes = NULL;
    memory_mappings[i].size = 0;
    memory_mappings[i].prot = 0;
    return empty_tuple;
}

//  s71: prim_epoll_create1

value
s71(value flags_value)
{
    int64_t flags = integer_decode(flags_value);
    int r = epoll_create1(flags);
    return integer_encode(r);
}

//  s60: prim_epoll_ctl

value
s60(value epoll_fd_value, value op_value, value fd_value, value event_chunk)
{
    int64_t epoll_fd = integer_decode(epoll_fd_value);
    int64_t op = integer_decode(op_value);
    int64_t fd = integer_decode(fd_value);
    value start_value = integer_encode(0);
    void *event = chunk_access(event_chunk, CHUNK_RW, start_value, 12);
    int r = epoll_ctl(epoll_fd, op, fd, event);
    return integer_encode(r);
}

//  s97: prim_epoll_wait

value
s97(value epoll_fd_value, value events_chunk, value max_events_value,
        value timeout_value)
{
    int64_t epoll_fd = integer_decode(epoll_fd_value);
    int64_t max_events = integer_decode(max_events_value);
    int64_t timeout = integer_decode(timeout_value);
    value start_value = integer_encode(0);
    unsigned n;
    if (__builtin_mul_overflow(max_events, 12, &n))
        die("Integer is out of range.");
    unsigned events_size = n;
    void *events = chunk_access(events_chunk, CHUNK_RW, start_value, events_size);
    int r = epoll_wait(epoll_fd, events, max_events, timeout);
    return integer_encode(r);
}

//  s04: prim_chunk_global

value
s04(value i_value)
{
    int32_t i = integer_decode(i_value);
    if (i < 0 || NUM_MEMORY_MAPPINGS <= i)
        die("Memory mapping index is out of range.");
    return global_chunk_encode(i);
}

//  s38: prim_chunk_new

value
s38(value num_bytes_value)
{
    int32_t num_bytes = integer_decode(num_bytes_value);
    if (num_bytes > CHUNK_NUM_BYTES_MAX)
        die("Chunk size is too big.");
    size_t align = _Alignof(struct chunk);
    size_t size = sizeof(struct chunk) + num_bytes;
    uint32_t id = heap_alloc(align, size);
    struct chunk *chunk_rep = heap_access(id);
    chunk_rep->header = chunk_header(CHUNK_RW, num_bytes);
    memset(chunk_rep->bytes, 0, num_bytes);
    return value_make_box(TAG_HEAP_CHUNK, id);
}

//  s32: prim_chunk_new_ro

value
s32(value num_bytes_value, value init_command_value)
{
    int32_t num_bytes = integer_decode(num_bytes_value);
    if (num_bytes > CHUNK_NUM_BYTES_MAX)
        die("Chunk size is too big.");
    size_t align = _Alignof(struct chunk);
    size_t size = sizeof(struct chunk) + num_bytes;
    uint32_t id = heap_alloc(align, size);
    struct chunk *chunk_rep = heap_access(id);
    chunk_rep->header = chunk_header(CHUNK_RW, num_bytes);
    memset(chunk_rep->bytes, 0, num_bytes);
    value chunk_value = value_make_box(TAG_HEAP_CHUNK, id);
    {
        uint32_t top = heap.top;
        value (*init_command)(value, value) = s35(init_command_value, 1);
        (void)init_command(init_command_value, chunk_value);
        heap.top = top;
    }
    chunk_rep->header = chunk_header(CHUNK_RO, num_bytes);
    return chunk_value;
}

//  s14: prim_chunk_size

value
s14(value chunk)
{
    if (value_has_tag(chunk, 0xf, TAG_HEAP_CHUNK)) {
        const struct chunk *chunk_rep = chunk_unbox(chunk);
        return integer_encode(chunk_num_bytes(chunk_rep));
    } else if (value_has_tag(chunk, 0xff, TAG_IMMEDIATE_CHUNK)) {
        int i = global_chunk_decode(chunk);
        return integer_encode(memory_mappings[i].size);
    }
    die("Value is not a chunk.");
}

//  s82: prim_chunk_store_bytes

value
s82(value d, value d_start_value, value s, value s_start_value, value count_value)
{
    int32_t count = integer_decode(count_value);
    if (count < 0)
        die("Chunk index range is invalid.");
    void *d_bytes = chunk_access(d, CHUNK_RW, d_start_value, count);
    const void *s_bytes = chunk_access(s, CHUNK_RO, s_start_value, count);
    memmove(d_bytes, s_bytes, count);
    return empty_tuple;
}

value
chunk_fetch_bytes(value chunk, value start_value, value count_value, int perm)
{
    int32_t count = integer_decode(count_value);
    if (count < 0)
        die("Chunk index range is invalid.");
    const void *bytes = chunk_access(chunk, CHUNK_RO, start_value, count);
    size_t align = _Alignof(struct chunk);
    size_t size = sizeof(struct chunk) + count;
    uint32_t id = heap_alloc(align, size);
    struct chunk *chunk_rep = heap_access(id);
    chunk_rep->header = chunk_header(perm, count);
    memmove(chunk_rep->bytes, bytes, count);
    return value_make_box(TAG_HEAP_CHUNK, id);
}

//  s11: prim_chunk_fetch_bytes_ro

value
s11(value chunk, value start_value, value count_value)
{
    return chunk_fetch_bytes(chunk, start_value, count_value, CHUNK_RO);
}

//  s39: prim_chunk_fetch_bytes_rw

value
s39(value chunk, value start_value, value count_value)
{
    return chunk_fetch_bytes(chunk, start_value, count_value, CHUNK_RW);
}

//  s42: prim_chunk_store_uint8

value
s42(value chunk, value i_value, value n_value)
{
    void *bytes = chunk_access(chunk, CHUNK_RW, i_value, 1);
    int64_t n = integer_decode(n_value);
    if (n < 0 || UINT8_MAX < n)
        die("Chunk value is out of range.");
    store_uint8(bytes, n);
    return empty_tuple;
}

//  s13: prim_chunk_fetch_uint8

value
s13(value chunk, value i_value)
{
    const void *bytes = chunk_access(chunk, CHUNK_RO, i_value, 1);
    uint8_t u = fetch_uint8(bytes);
    static_assert(UINT8_MAX <= INTEGER_MAX);
    return integer_encode(u);
}

//  s76: prim_chunk_store_int8_le

value
s76(value chunk, value i_value, value n_value)
{
    void *bytes = chunk_access(chunk, CHUNK_RW, i_value, 1);
    int64_t s = integer_decode(n_value);
    if (s < INT8_MIN || INT8_MAX < s)
        die("Number is out of range.");
    store_int8(bytes, s);
    return empty_tuple;
}

//  s46: prim_chunk_fetch_int8_le

value
s46(value chunk, value i_value)
{
    const void *bytes = chunk_access(chunk, CHUNK_RO, i_value, 1);
    int64_t s = fetch_int8(bytes);
    if (s < INTEGER_MIN || INTEGER_MAX < s)
        die("Number is out of range.");
    return integer_encode(s);
}

//  s54: prim_chunk_store_uint16_le

value
s54(value chunk, value i_value, value n_value)
{
    void *bytes = chunk_access(chunk, CHUNK_RW, i_value, 2);
    int64_t n = integer_decode(n_value);
    if (n < 0 || UINT16_MAX < n)
        die("Chunk value is out of range.");
    store_uint16_le(bytes, n);
    return empty_tuple;
}

//  s29: prim_chunk_fetch_uint16_le

value
s29(value chunk, value i_value)
{
    const void *bytes = chunk_access(chunk, CHUNK_RO, i_value, 2);
    uint16_t u = fetch_uint16_le(bytes);
    static_assert(UINT16_MAX <= INTEGER_MAX);
    return integer_encode(u);
}

//  s08: prim_chunk_store_int16_le

value
s08(value chunk, value i_value, value n_value)
{
    void *bytes = chunk_access(chunk, CHUNK_RW, i_value, 2);
    int64_t s = integer_decode(n_value);
    if (s < INT16_MIN || INT16_MAX < s)
        die("Number is out of range.");
    store_int16_le(bytes, s);
    return empty_tuple;
}

//  s98: prim_chunk_fetch_int16_le

value
s98(value chunk, value i_value)
{
    const void *bytes = chunk_access(chunk, CHUNK_RO, i_value, 2);
    int64_t s = fetch_int16_le(bytes);
    if (s < INTEGER_MIN || INTEGER_MAX < s)
        die("Number is out of range.");
    return integer_encode(s);
}

//  s74: prim_chunk_store_uint32_le

value
s74(value chunk, value i_value, value n_value)
{
    void *bytes = chunk_access(chunk, CHUNK_RW, i_value, 4);
    int64_t n = integer_decode(n_value);
    if (n < 0 || UINT32_MAX < n)
        die("Chunk value is out of range.");
    store_uint32_le(bytes, n);
    return empty_tuple;
}

//  s01: prim_chunk_fetch_uint32_le

value
s01(value chunk, value i_value)
{
    const void *bytes = chunk_access(chunk, CHUNK_RO, i_value, 4);
    uint32_t u = fetch_uint32_le(bytes);
    if (u > INTEGER_MAX)
        die("Number is out of range.");
    return integer_encode(u);
}

//  s17: prim_chunk_store_int32_le

value
s17(value chunk, value i_value, value n_value)
{
    void *bytes = chunk_access(chunk, CHUNK_RW, i_value, 4);
    int64_t s = integer_decode(n_value);
    if (s < INT32_MIN || INT32_MAX < s)
        die("Number is out of range.");
    store_int32_le(bytes, s);
    return empty_tuple;
}

//  s59: prim_chunk_fetch_int32_le

value
s59(value chunk, value i_value)
{
    const void *bytes = chunk_access(chunk, CHUNK_RO, i_value, 4);
    int64_t s = fetch_int32_le(bytes);
    if (s < INTEGER_MIN || INTEGER_MAX < s)
        die("Number is out of range.");
    return integer_encode(s);
}

//  s21: prim_chunk_store_uint64_le

value
s21(value chunk, value i_value, value n_value)
{
    void *bytes = chunk_access(chunk, CHUNK_RW, i_value, 8);
    int64_t n = integer_decode(n_value);
    if (n < 0 || UINT64_MAX < n)
        die("Chunk value is out of range.");
    store_uint64_le(bytes, n);
    return empty_tuple;
}

//  s99: prim_chunk_fetch_uint64_le

value
s99(value chunk, value i_value)
{
    const void *bytes = chunk_access(chunk, CHUNK_RO, i_value, 8);
    uint64_t u = fetch_uint64_le(bytes);
    if (u > INTEGER_MAX)
        die("Number is out of range.");
    return integer_encode(u);
}

//  s58: prim_chunk_store_int64_le

value
s58(value chunk, value i_value, value n_value)
{
    void *bytes = chunk_access(chunk, CHUNK_RW, i_value, 8);
    int64_t s = integer_decode(n_value);
    if (s < INT64_MIN || INT64_MAX < s)
        die("Number is out of range.");
    store_int64_le(bytes, s);
    return empty_tuple;
}

//  s80: prim_chunk_fetch_int64_le

value
s80(value chunk, value i_value)
{
    const void *bytes = chunk_access(chunk, CHUNK_RO, i_value, 8);
    int64_t s = fetch_int64_le(bytes);
    if (s < INTEGER_MIN || INTEGER_MAX < s)
        die("Number is out of range.");
    return integer_encode(s);
}
