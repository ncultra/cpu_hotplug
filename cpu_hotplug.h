#ifndef __CPU_HOTPLUG_H
#define __CPU_HOTPLUG_H

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/cpu.h>
#include <linux/cpuhotplug.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <uapi/linux/un.h>
#include <net/sock.h>
#include <net/net_namespace.h>
#include <net/tcp_states.h>
#include <linux/kthread.h>
#include <linux/moduleparam.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/namei.h>
#include <linux/list.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/semaphore.h>
#include <linux/spinlock.h>
#include <linux/compiler.h>
#include <asm/atomic64_64.h>
#include <linux/printk.h>
#include <linux/kallsyms.h>
#include <linux/preempt.h>
#include <linux/cpumask.h>
#include <linux/random.h>
#include <linux/uuid.h>
#include <linux/jiffies.h>

#define _MODULE_LICENSE "GPL v2"
#define _MODULE_AUTHOR "Mike Day"
#define _MODULE_INFO "cpu hot-plug demo"

#define assert(s) do {							\
		if (unlikely(!(s))) printk(KERN_DEBUG "assertion failed: " #s " at %s:%d\n", \
					   __FILE__, __LINE__);		\
	} while(0)

extern atomic64_t SHOULD_SHUTDOWN;
extern struct list_head connections;
extern struct connection *listener;
extern char *socket_name;
extern uint32_t protocol_version;
extern uuid_t driver_uuid;
extern uint32_t map_length;


extern unsigned int nr_cpu_ids;
extern struct cpumask __cpu_possible_mask, __cpu_online_mask;
extern struct cpumask __cpu_present_mask, __cpu_active_mask;


/**
 * TODO:  https://lwn.net/Articles/588444/
 * checking for unused flags
 **/

#define __SET_FLAG(flag, bits) ((flag) |= (bits))
#define __CLEAR_FLAG(flag, bits) ((flag) &= ~(bits))
#define __FLAG_IS_SET(flag, bits) ((flag) & (bits) ? 1 : 0)
#define __FLAG_IS_IS_CLEAR(flag, bits) ((flag) & (bits) ? 0 : 1)

#define SOCK_LISTEN       (1 << 0)
#define SOCK_CONNECTED    (1 << 1)
#define SOCK_HAS_WORK     (1 << 2)
#define CONNECTION_CLOSED (1 << 3)
/**
 * message protocol version
 * note: NETWORK BYTE ORDER
 *    0                   1                   2                   3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |    release    |    minor      |  major        | reserved      |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 **/

#define GET_MAJOR_VERSION(v) (((v) & 0xff0000) >> 16)
#define GET_MINOR_VERSION(v) (((v) & 0x00ff00) >> 8)
#define GET_RELEASE_VERSION(v) ((v) & 0xff)


/**
 * GET_BOOT_STATE rep->current_state values
 * see linux/include/linux/cpu.h
 * These states are not related to the core CPU hotplug mechanism. They are
 * used by various (sub)architectures to track internal state
 **/
#define CPU_ONLINE		0x0002 /* CPU is up */
#define CPU_UP_PREPARE		0x0003 /* CPU coming up */
#define CPU_DEAD		0x0007 /* CPU dead */
#define CPU_DEAD_FROZEN		0x0008 /* CPU timed out on unplug */
#define CPU_POST_DEAD		0x0009 /* CPU successfully unplugged */
#define CPU_BROKEN		0x000B /* CPU did not die properly */


enum message_type {EMPTY = 0, REQUEST, REPLY, COMPLETE};
/**
 * messages to add:
 * cpu_hotplug enable see comment in kernel/cpu.c:281
 * cpu_hotplug disable
 * get_{possible, present, available, active} masks
 **/
enum message_action {ZERO = 0, DISCOVER, UNPLUG, PLUG, GET_BOOT_STATE, GET_CURRENT_STATE, SET_TARGET_STATE,
                     GET_CPU_BITMASKS, SET_DRIVER_UUID, SET_MAP_LENGTH, LAST};
enum message_errors {OK = 0, _EINVAL = 2, MSG_TYPE, MSG_VERSION, NOT_HANDLED, _EBUSY, _EPERM, NOT_IMPL,
		     _ENOMEM, _EBADF, _ERANGE};

/** see linux/include/cpumask.h and kernel/cpu.c exported bitmasks **/

#define MAX_NR_CPUS 512
/**
 * @note: usually will be called using nr_cpu_ids
 *        safe_cpu_bits(nr_cpu_ids);
 **/
static inline int safe_cpu_bits(int actual_cpu_ids)
{
	if (actual_cpu_ids <= MAX_NR_CPUS) {
		return actual_cpu_ids;
	}
	return MAX_NR_CPUS;
}

/**
 * @brief: struct hotplug_msg a 304-byte binary message format, intended to work
 *         equally well for memory-mapped registers or serialized media
 *
 * @magic: message header that must be equal to CONNECTION_MAGIC (0xf8cb820d)
 * @version: four-byte network order with major, minor, release, reserved fields
 * @nonce: message id - request and reply should have the same nonce
 * @msg_type: request (1) or reply (2)
 * @cpu: logical cpu number (zero-indexed), has special significance for bitmap requests
 * @action: command plug, unplug, etc.
 * @current_state: current state of cpu (valid only for reply message)
 * @target_state: target state of cpu (setting will initiate a state change)
 * @result: return or error code of action (valid only for reply message)
 * @uuid: domain identifier, identifies target of command and source of reply
 * @map_length: how many bits are valid in the following bitmaps
 * @possible_mask: 512-bit map, 1 bit set for each possible cpu
 * @present_mask: 512-bit map, 1 bit set for each present (populated) cpu
 * @online_mask: 512-bit map, 1 bit set for each online cpu
 * @active_mask: 512-bit map, 1 bit set for each powered cpu (could be hot-unplugged)
 * @cycles: when non-zero, contains the number of cycles consumed by the current
 *          operation
 *
 * all fields are present in both request and reply messages. By convention, unused
 * fields are zeroed.
 **/
struct hotplug_msg
{
	uint32_t magic;            /* 0 */
	uint32_t version;          /* 4 */
	uint64_t nonce;            /* 8 */
	uint32_t msg_type;         /* 16 */
	uint32_t cpu;              /* 20 logical cpu */
	uint32_t action;           /* 24 0 == unplug, 1 = plug  */
	uint32_t current_state;    /* 28 */
	uint32_t target_state;     /* 32 */
	uint32_t result;           /* 36 0 == success, non-zero == error */
	uuid_t uuid;               /* 40  -- domain uuid 16 bytes */
	uint32_t map_length;       /* 56 -- valid bytes in cpu maps below */

	/**
	 * see include/linux/cpumask.h for definitions.
	 * assume 512 potential cpu IDs.
	 **/
	uint64_t possible_mask[8]; /*  60 */
	uint64_t present_mask[8];  /* 124 */
	uint64_t online_mask[8];   /* 188 */
	uint64_t active_mask[8];   /* 252 */
	uint64_t cycles;           /* 316 */
} __attribute__((packed));   /* 324 bytes */

#define OFFSET_MAGIC           0
#define OFFSET_VERSION         4
#define OFFSET_NONCE           8
#define OFFSET_MSG_TYPE       16
#define OFFSET_CPU            20
#define OFFSET_ACTION         24
#define OFFSET_CURRENT_STATE  28
#define OFFSET_TARGET_STATE   32
#define OFFSET_RESULT         36
#define OFFSET_UUID           40
#define OFFSET_MAP_LENGTH     56
#define OFFSET_POSSIBLE_MASK  60
#define OFFSET_PRESENT_MASK  124
#define OFFSET_ONLINE_MASK   188
#define OFFSET_ACTIVE_MASK   252
#define OFFSET_CYCLES        316
/**
 * sizeof(struct hotplug_msg) == 324
 **/

#define CONNECTION_MAGIC ((uint32_t)0xf8cb820d)
#define CONNECTION_MAX_HEADER sizeof(struct hotplug_msg)
#define CONNECTION_MAX_REQUEST CONNECTION_MAX_HEADER
#define CONNECTION_MAX_BUFFER CONNECTION_MAX_HEADER
#define CONNECTION_MAX_MESSAGE CONNECTION_MAX_HEADER
#define CONNECTION_MAX_REPLY CONNECTION_MAX_HEADER
#define CONNECTION_PATH_MAX 0x200

/* connection struct is used for both listening and connected sockets */
/* function pointers for listen, accept, close */
struct connection {
	struct list_head l;
	uint64_t flags;
	struct semaphore s_lock;
	struct kthread_work work;
	struct kthread_worker *worker;
	struct socket *connected;
	uint8_t path[CONNECTION_PATH_MAX];
};

/**
 * call with c->s_lock held
 **/
static inline void mark_conn_closed(struct connection *c)
{
	__CLEAR_FLAG(c->flags, SOCK_CONNECTED);
	__SET_FLAG(c->flags, CONNECTION_CLOSED);
}

struct sym_import {
	char name[KSYM_NAME_LEN];
	uint64_t addr;
};

extern struct sym_import sym_imports[];
#define SIZE_IMPORTS (sizeof(sym_imports) / sizeof(struct sym_import))

static inline int check_magic(struct hotplug_msg *m)
{
	if (m) {
		if (m->magic == CONNECTION_MAGIC) {
			return 1;
		}
	}
	return 0;
}

/**
 * @brief: return 1 if all three version components (major, minor, release) match
 **/
static inline int check_version(struct hotplug_msg *m)
{
	if (!m) {
		return 0;
	}
	if (GET_MAJOR_VERSION(m->version) ==
	    GET_MAJOR_VERSION(protocol_version)) {
		if (GET_MINOR_VERSION(m->version) ==
		    GET_MINOR_VERSION(protocol_version)) {
			if (GET_RELEASE_VERSION(m->version) ==
			    GET_RELEASE_VERSION(protocol_version)) {
				return 1;
			}
		}
	}
	return 0;
}



static inline uint64_t read_timer(void)
{
	return get_jiffies_64();
}

static inline uint64_t cycles_elapsed(uint64_t begin, uint64_t end)
{
	uint64_t elapsed = 0;
	if (time_after(((unsigned long)end), ((unsigned long)begin))) {
		if (end < begin) {
			elapsed = (~0ULL - begin) + end;
		}
		else {
			elapsed = end - begin;
		}
	}
	return elapsed;
}

static inline uint64_t __attribute__((used)) msecs_elapsed(uint64_t begin, uint64_t end)
{
	return jiffies_to_msecs(cycles_elapsed(begin, end));
}

/**
 * @brief: return 1 if the major version matches
 *         a major version guarantees message structure and protocol
 *         compatibility.
 **/

static inline int maj_ver_compat(struct hotplug_msg *m)
{
	if (!m) {
		return 0;
	}
	if (GET_MAJOR_VERSION(m->version) == GET_MAJOR_VERSION(protocol_version)) {
		return 1;
	}

	return 0;
}

static inline void gen_nonce(uint64_t *nonce)
{
	if (nonce) {
		get_random_bytes(nonce, sizeof(uint64_t));
	}
	return;
}

static inline bool check_nonce(struct hotplug_msg *req, struct hotplug_msg *rep)
{
	if (req && rep) {
		if (req->nonce == rep->nonce) {
			return 1;
		}
	}
	return 0;
}

void free_message(struct hotplug_msg *m);
struct hotplug_msg *new_message(uint8_t *buf, size_t len);

int parse_hotplug_req(struct hotplug_msg *req, struct hotplug_msg *rep);

typedef int (*dispatch_t)(struct hotplug_msg *, struct hotplug_msg *);
dispatch_t dispatch_table[];

size_t k_socket_read(struct socket *sock,
		     size_t size,
		     void *in,
		     unsigned int flags);

size_t k_socket_peak(struct socket *sock);

size_t k_socket_write(struct socket *sock,
		      size_t size,
		      void *out,
		      unsigned int flags);

int unlink_file(char *filename);
int file_getattr(struct file *f, struct kstat *k);
size_t write_online(int cpu, bool state);
size_t write_file(char *name, void *buf, size_t count, loff_t * pos);
size_t vfs_read_file(char *name, void **buf, size_t max_count, loff_t *pos);

struct connection *init_connection(struct connection *c, uint64_t flags, void *p);
int __init socket_interface_init(void);
void __exit socket_interface_exit(void);

#endif /** __CPU_HOTPLUG_H **/
