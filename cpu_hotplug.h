#ifndef __CPU_HOTPLUG_H
#define __CPU_HOTPLUG_H

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
#include <linux/namei.h>
#include <linux/rculist.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/semaphore.h>
#include <linux/spinlock.h>
#include <linux/compiler.h>
#include <asm/atomic64_64.h>
#include <linux/printk.h>

extern atomic64_t SHOULD_SHUTDOWN;
extern struct list_head connections;
extern struct connection listener;
extern char *socket_name;
extern uint32_t protocol_version;


#define _MODULE_LICENSE "GPL v2"
#define _MODULE_AUTHOR "Mike Day"
#define _MODULE_INFO "cpu hot-plug demo"

#define assert(s) do { \
	if (unlikely(!(s))) printk(KERN_DEBUG "assertion failed: " #s " at %s:%d\n", \
				   __FILE__, __LINE__);			\
} while(0)


/**
 * TODO:  https://lwn.net/Articles/588444/
 * checking for unused flags
 **/

#define __SET_FLAG(flag, bits) ((flag) |= (bits))
#define __CLEAR_FLAG(flag, bits) ((flag) &= ~(bits))
#define __FLAG_IS_SET(flag, bits) ((flag) & (bits) ? 1 : 0)
#define __FLAG_IS_IS_CLEAR(flag, bits) ((flag) & (bits) ? 0 : 1)

#define SOCK_LISTEN    (1 << 0)
#define SOCK_CONNECTED (1 << 1)
#define SOCK_HAS_WORK  (1 << 2)


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

enum message_type {EMPTY = 0, REQUEST, REPLY, COMPLETE};
enum message_action {ZERO = 0, DISCOVER, UNPLUG, PLUG, GET_CURRENT_STATE, SET_TARGET_STATE, LAST};
/** see linux/include/cpumask.h and kernel/cpu.c exported bitmasks **/


struct hotplug_msg
{
	uint32_t magic; /* 0 */
	uint32_t version; /* 4 */
	uint32_t msg_type; /* 8 */
	uint32_t cpu;    /* 12 logical cpu */
	uint32_t action; /* 16 0 == unplug, 1 = plug  */
	uint32_t current_state; /* 20 */
	uint32_t target_state; /* 24 */
	uint32_t result; /* 28 0 == success, non-zero == error */
  /**
   * see include/linux/cpumask.h for definitions.
   * assume 512 potential cpu IDs.
   **/
  uint64_t possible_mask[8]; /* 32 */
  uint64_t present_mask[8]; /* 96 */
  uint64_t online_mask[8]; /* 160 */
  uint64_t active_mask[8]; /* 224 */
} __attribute__((packed));

#define CONNECTION_MAGIC ((uint32_t)0xf8cb820d)
#define CONNECTION_MAX_HEADER sizeof(struct hotplug_msg)
#define CONNECTION_MAX_REQUEST CONNECTION_MAX_HEADER
#define CONNECTION_MAX_BUFFER CONNECTION_MAX_HEADER
#define CONNECTION_MAX_MESSAGE CONNECTION_MAX_HEADER
#define CONNECTION_MAX_REPLY CONNECTION_MAX_HEADER
#define CONNECTION_PATH_MAX 0x200

static inline int check_magic(struct hotplug_msg *m)
{
	if (m) {
		if (m->magic == CONNECTION_MAGIC) {
			return 1;
		}
	}
	return 0;
}

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


/* connection struct is used for both listening and connected sockets */
/* function pointers for listen, accept, close */
struct connection {
	struct list_head l;
	uint64_t magic;
	uint64_t flags;
	struct semaphore s_lock;
	struct kthread_work work;
	struct kthread_worker worker;
	struct socket *connected;
	uint8_t path[CONNECTION_PATH_MAX];
};


struct connection *init_connection(struct connection *c, uint64_t flags, void *p);


/** kthread stuff **/

#define CONT_CPU_ANY -1
struct kthread_worker *create_worker(unsigned int flags, const char namefmt[], ...);

void destroy_worker(struct kthread_worker *worker);

void *destroy_work(struct kthread_work *work);

bool init_and_queue_work(struct kthread_work *work,
			 struct kthread_worker *worker,
			 void (*function)(struct kthread_work *));


int __init socket_interface_init(void);
void __exit socket_interface_exit(void);

#endif /** __CPU_HOTPLUG_H **/
