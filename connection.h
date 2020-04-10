#ifndef __CONNECTION_H
#define __CONNECTION_H

#include <linux/types.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <linux/kthread.h>
#include <linux/moduleparam.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/list.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/semaphore.h>
#include <linux/spinlock.h>
#include <linux/compiler.h>
#include <asm/atomic64_64.h>

extern atomic64_t SHOULD_SHUTDOWN;
extern struct list_head connections;
extern struct connection listener;
extern char *socket_name;

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

enum message_type {EMPTY, REQUEST, REPLY, COMPLETE};
enum message_action {UNPLUG, PLUG, CURRENT_STATE, TARGET_STATE};
/** see kernel/cpu.c exported bitmasks **/


struct hotplug_msg
{
	uint64_t magic;
	uint64_t msg_type;
	uint64_t cpu;    /* logical cpu */
	uint64_t action; /* 0 == unplug, 1 = plug  */
	uint64_t current_state;
	uint64_t target_state;
	uint64_t result; /* 0 == success, non-zero == error */
} __attribute__((packed));

#define CONNECTION_MAGIC ((uint64_t)0xf8cb820d8900dbdb) /** fits into a 64-bit var **/
#define CONNECTION_MAGIC_LEN sizeof(uint64_t)
#define CONNECTION_MAX_HEADER sizeof(struct hotplug_msg)
#define CONNECTION_MAX_REQUEST CONNECTION_MAX_HEADER
#define CONNECTION_MAX_BUFFER CONNECTION_MAX_HEADER
#define CONNECTION_MAX_MESSAGE CONNECTION_MAX_HEADER
#define CONNECTION_MAX_REPLY CONNECTION_MAX_HEADER
#define CONNECTION_PATH_MAX CONNECTION_MAX_HEADER

static inline int check_magic(uint64_t *magic)
{
	if (magic) {
		if (*magic == CONNECTION_MAGIC) {
			return 1;
		}
	}
	return 0;
}

void free_message(struct hotplug_msg *m);
struct hotplug_msg *new_message(uint8_t *buf, size_t len);

int parse_hotplug_msg(struct hotplug_msg *m);


ssize_t k_socket_read(struct socket *sock,
		      size_t size,
		      void *in,
		      unsigned int flags);

ssize_t k_socket_peak(struct socket *sock);

ssize_t k_socket_write(struct socket *sock,
		       size_t size,
		       void *out,
		       unsigned int flags);


/* connection struct is used for both listening and connected sockets */
/* function pointers for listen, accept, close */
struct connection {
	/**
	 * _init parameters:
	 * uint64_t flags - will have the PROBE_LISTENER or PROBE_CONNECTED bit set
	 * void * data depends on the value of flags:
	 *    if __FLAG_IS_SET(flags, PROBE_LISTENER), then data points to a
	 *    string in the form of "/var/run/socket-name".
	 *    if __FLAG_IS_SET(flags, PROBE_CONNECTED, then data points to a
	 *    struct socket
	 **/
	struct list_head l;
	uint64_t magic;
	uint64_t flags;
	struct semaphore s_lock;
	struct kthread_work work;
	struct kthread_worker;
	struct socket *connected;
	uint8_t path[CONNECTION_PATH_MAX];
};


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


#endif /** __CONNECTION_H **/
