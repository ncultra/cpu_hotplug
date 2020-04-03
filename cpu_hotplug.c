#include "cpu_hotplug.h"


/**
 * sock refers to struct socket,
 * sk refers to struct sock
 * http://haifux.org/hebrew/lectures/217/netLec5.pdf
 **/
static __attribute((used)) ssize_t k_socket_read(struct socket *sock,
						 size_t size,
						 void *in,
						 unsigned int flags)
{

	ssize_t res = 0;
	struct msghdr msg = {.msg_flags = flags};
	struct kvec iov = {.iov_base = in, .iov_len = size};

	printk(KERN_DEBUG "k_socket_read sock %p, num bytes to read %ld," \
		   "inbuf %p, flags %x\n",
		   sock, size, in, flags);
again:
	res = kernel_recvmsg(sock, &msg, &iov, 1, size, flags);
	if (res == -EAGAIN)
		goto again;

	return res;
}


static __attribute((used)) ssize_t k_socket_peak(struct socket *sock)
{
	static uint8_t in[MAX_MESSAGE];

	return k_socket_read(sock, MAX_MESSAGE, in, MSG_PEEK);
}


static ssize_t __attribute((used)) k_socket_write(struct socket *sock,
						  size_t size,
						  void *out,
						  unsigned int flags)
{
	ssize_t res = 0;
	struct msghdr msg = {.msg_flags = flags};
	struct kvec iov = {.iov_base = out, .iov_len = size};

again:
	res = kernel_sendmsg(sock, &msg, &iov, 1, size);
	if (res <= 0) {
		if (res == -EAGAIN) {
			yield();
			goto again;
		}
		printk(KERN_DEBUG "kernel_sendmsg returned err %lx\n", res);
	}
	return res;
}

static int my_cpu_online(unsigned int cpu)
{
	int ccode = 0;
	printk(KERN_DEBUG "cpu %d coming online\n", cpu);
	return ccode;
}


static int my_cpu_going_offline(unsigned int cpu)
{
	int ccode = 0;
	printk(KERN_DEBUG "cpu %d going offline\n", cpu);
	return ccode;
}

static int __init cpu_hotplug_init(void)
{
	int ccode = 0;
	printk(KERN_DEBUG "cpu hotplug demo module\n");
	ccode = cpuhp_setup_state(CPUHP_AP_ONLINE_DYN,
                            "x86/demo:online",
                            my_cpu_online,
                            my_cpu_going_offline);

	printk(KERN_DEBUG "cpuhp_setup_state returned %d\n", ccode);
	return 0;
}

static void __exit cpu_hotplug_cleanup(void)
{
	printk(KERN_DEBUG "cpu hotplug demo unloading...\n");
	cpuhp_remove_state(CPUHP_AP_ONLINE_DYN);
}



module_init(cpu_hotplug_init);
module_exit(cpu_hotplug_cleanup);


MODULE_LICENSE(_MODULE_LICENSE);
MODULE_AUTHOR(_MODULE_AUTHOR);
MODULE_DESCRIPTION(_MODULE_INFO);
