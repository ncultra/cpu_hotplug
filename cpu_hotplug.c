#include "cpu_hotplug.h"
atomic64_t SHOULD_SHUTDOWN = ATOMIC64_INIT(0);
EXPORT_SYMBOL(SHOULD_SHUTDOWN);

DEFINE_SPINLOCK(connections_lock);
LIST_HEAD(connections);
struct connection listener = {{0,0},};
EXPORT_SYMBOL(listener);

uint32_t protocol_version = 0x010000;
EXPORT_SYMBOL(protocol_version);

char *socket_name = "/var/run/cpu_hotplug.sock";
char *lockfile_name = "/var/run/cpu_hotplug.lock";
module_param(socket_name, charp, 0644);

static inline void init_reply(struct hotplug_msg *req, struct hotplug_msg *rep)
{
	if (req && rep) {
		rep->magic = req->magic;
		rep->version = req->version;
		rep->msg_type = REPLY;
		rep->cpu = req->cpu;
		rep->action = req->action;
		rep->result = 0;
	}
	return;
}

static int handle_invalid(struct hotplug_msg *req, struct hotplug_msg *rep)
{
	init_reply(req, rep);
	return EINVAL;
}

static int handle_discover(struct hotplug_msg *req, struct hotplug_msg *rep)
{
	init_reply(req, rep);
	return 0;
}

int handle_unplug(struct hotplug_msg *req, struct hotplug_msg *rep)
{
	init_reply(req, rep);
	return 0;
}

int handle_plug(struct hotplug_msg *req, struct hotplug_msg *rep)
{
	init_reply(req, rep);
	return 0;
}

int handle_get_cur_state(struct hotplug_msg *req, struct hotplug_msg *rep)
{
	init_reply(req, rep);
	return 0;
}

int handle_set_cur_state(struct hotplug_msg *req, struct hotplug_msg *rep)
{
	init_reply(req, rep);
	return 0;
}

dispatch_t dispatch_table[] = {
	handle_invalid,
	handle_discover,
	handle_unplug,
	handle_plug,
	handle_get_cur_state,
	handle_set_cur_state,
	handle_invalid
};

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

/**
 * check magic
 * validate cpu number
 * validate action
 * perform action
 * return zero or error code
 **/
int parse_hotplug_req(struct hotplug_msg *request, struct hotplug_msg *response)
{
	if (!request || !response) {
		return -EINVAL;
	}

	if (!check_magic(request) || !check_version(request)) {
		return -EINVAL;
	}

	if (request->msg_type == REQUEST &&
	    request->action > ZERO &&
	    request->action < LAST) {
		return dispatch_table[request->action](request, response);
	}
	return -EINVAL;
}

/**
 * free_message - and don't free the socket (kernel space)
 * or close the file (user space). The other end of the
 * connection may write or read using this socket (file)
 **/
void free_message(struct hotplug_msg *m)
{
	if (m) {
		kzfree(m);
	}

	return;
}

struct hotplug_msg *new_message(uint8_t *buf, size_t len)
{
	struct hotplug_msg *m = NULL;

	if (!buf || len > CONNECTION_MAX_BUFFER || buf[len] != 0x00) {
		return NULL;
	}
	m = kzalloc(sizeof(struct hotplug_msg), GFP_KERNEL);
	if (!m) {
		return NULL;
	}
	return m;
}




/**
 * sock refers to struct socket,
 * sk refers to struct sock
 * http://haifux.org/hebrew/lectures/217/netLec5.pdf
 **/
size_t k_socket_read(struct socket *sock,
		     size_t size,
		     void *in,
		     unsigned int flags)
{

	size_t res = 0;
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


void *read_alloc_buf(struct socket *sock,
		     size_t max_size,
		     size_t *actual_size)
{

	void *buf = NULL;
	size_t bytes_read = 0;

	if (!sock || !actual_size || max_size <= 0) {
		return NULL;
	}
	if (max_size > CONNECTION_MAX_MESSAGE) {
		printk(KERN_DEBUG "truncating max_size from %ld to %ld\n",
		       max_size, CONNECTION_MAX_MESSAGE);
		max_size = CONNECTION_MAX_MESSAGE;
	}

	*actual_size = 0;

	buf = kzalloc(max_size, GFP_KERNEL);
	if (buf == NULL) {
		printk(KERN_DEBUG "kzalloc returned NULL\n");
		return buf;
	}

	bytes_read = k_socket_read(sock, max_size, buf, 0);
	if (bytes_read <= 0) {
		if (bytes_read < 0) {
			printk(KERN_DEBUG "recvmsg returned error %ld\n", bytes_read);
		}
		else if (bytes_read == 0) {
			printk(KERN_DEBUG "recvmsg read zero bytes\n");
		}
		kfree(buf);
		return NULL;
	}
	if (unlikely(bytes_read > max_size)) {
		printk(KERN_DEBUG "recvmsg returned > max size, shouldn't happen!\n");
		kzfree(buf);
		return NULL;
	}
	*actual_size = bytes_read;
	if (max_size != *actual_size) {
		buf = krealloc(buf, bytes_read, GFP_KERNEL);
	}

	return buf;
}



size_t k_socket_write(struct socket *sock,
		       size_t size,
		       void *out,
		       unsigned int flags)
{
	size_t res = 0;
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

bool init_and_queue_work(struct kthread_work *work,
			 struct kthread_worker *worker,
			 void (*function)(struct kthread_work *))
{


	kthread_init_work(work, function);
	return kthread_queue_work(worker, work);

}


static void k_accept(struct kthread_work *work)
{
	int ccode = 0;

	struct connection *new_connection = NULL;
	struct socket *newsock = NULL;
	struct kthread_worker *worker = work->worker;
	struct connection *connection = container_of(work, struct connection, work);

	/**
	 * the unix socket implementation masks out MSG_DONTWAIT,
	 * and then uses O_NONBLOCK internally when handling queued skbs.
	 * the result is that unix accept always blocks.
	 **/

	if (down_interruptible(&connection->s_lock))
		goto close_out_reschedule;

	if (! atomic64_read(&SHOULD_SHUTDOWN)) {
		if ((ccode = kernel_accept(connection->connected,
					   &newsock,
					   0L)) < 0)
		{
			printk(KERN_DEBUG "k_accept returned error %d, exiting\n",
				   ccode);
			goto close_out_quit;
		}
	}
        /**
	 * create a new struct connection, link it to the global connections list
	 **/
	if (newsock != NULL && (! atomic64_read(&SHOULD_SHUTDOWN))) {
		new_connection = kzalloc(sizeof(struct connection), GFP_KERNEL);
		if (new_connection) {
			init_connection(new_connection, SOCK_CONNECTED, newsock);
		} else {
			atomic64_set(&SHOULD_SHUTDOWN, 1);
		}
	}
close_out_reschedule:
	if (! atomic64_read(&SHOULD_SHUTDOWN)) {
		init_and_queue_work(work, worker, k_accept);
	}
close_out_quit:
	up(&connection->s_lock);

	return;
}

static int start_listener(struct connection *c)
{
	struct sockaddr_un addr = {.sun_family = AF_UNIX};
	struct socket *sock = NULL;

	assert(__FLAG_IS_SET(c->flags, SOCK_LISTEN));
	sock_create_kern(&init_net, AF_UNIX, SOCK_STREAM, 0, &sock);

	if (!sock) {
		c->connected = NULL;
		goto err_exit;
	}
	c->connected = sock;
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	memcpy(addr.sun_path, &c->path[0], sizeof(addr.sun_path));

	/* sizeof(address) - 1 is necessary to ensure correct null-termination */
	if (kernel_bind(sock, (struct sockaddr *)&addr, sizeof(addr) -1)) {
		goto err_release;

	}
/* see /usr/include/net/tcp_states.h */
	if (kernel_listen(sock, TCP_LISTEN)) {
		kernel_sock_shutdown(sock, RCV_SHUTDOWN | SEND_SHUTDOWN);
		goto err_release;
	}

	return 0;
err_release:

	sock_release(sock);
err_exit:
	c->connected = NULL;
	return -ENFILE;
}

static void link_new_connection_work(struct connection *c,
				     struct list_head *l,
				     void (*f)(struct kthread_work *),
				     uint8_t *d)
{

	if (! atomic64_read(&SHOULD_SHUTDOWN)) {
		spin_lock(&connections_lock);
		list_add_rcu(&c->l, l);
		spin_unlock(&connections_lock);
		kthread_init_work(&c->work, f);
		__SET_FLAG(c->flags, SOCK_HAS_WORK);
		kthread_init_worker(&c->worker);
		kthread_queue_work(&c->worker, &c->work);
		kthread_run(kthread_worker_fn, &c->worker, d);
	}

}

/**
 * tear down the connection but don't free the connection
 * memory. do free resources, struct sock.
 **/
static void *destroy_connection(struct connection *c)
{
	if (down_interruptible(&c->s_lock))
		return c;

	if (c->connected) {
		kernel_sock_shutdown(c->connected, SHUT_RDWR);
		sock_release(c->connected);
		c->connected = NULL;
	}
	up(&c->s_lock);
	memset(c, 0x00, sizeof(*c));
	return c;
}


/**
 * dispatched from a kernel thread, has a connected socket
 * read and write cpu hotplug messages. If encountering an error, close the socket.
 * if no error, re-schedule the kernel thread to run again.
 **/
static void k_msg_server(struct kthread_work *work)
{
	int ccode = 0;
	size_t read_size = 0;
	uint8_t * read_buf = NULL;
	struct socket *sock = NULL;
	struct kthread_worker *worker = NULL;
	struct connection *connection = NULL;

	if (! work) {
		printk(KERN_DEBUG "message server: invalid parameter\n");
		return;
	}

	worker = work->worker;
	connection = container_of(work, struct connection, work);
	if (! connection->connected) {
		printk(KERN_DEBUG "message server: invalid socket\n");
		goto close_out;
	}

	if (! (__FLAG_IS_SET(connection->flags, SOCK_CONNECTED) &&
	       __FLAG_IS_SET(connection->flags, SOCK_HAS_WORK))) {
		printk(KERN_DEBUG "message server: invalid connection flags\n");
		goto close_out;
	}

	if (! connection->connected) {
		printk(KERN_DEBUG "message server: no socket!\n");
		goto close_out;
	}

	ccode = down_interruptible(&connection->s_lock);
	if (ccode) {
		printk(KERN_DEBUG "message server: unable to down connection semaphore\n");
		goto close_out;
	}

	sock = connection->connected;
	read_buf = read_alloc_buf(sock, CONNECTION_MAX_MESSAGE, &read_size);
	if (read_buf && read_size == CONNECTION_MAX_MESSAGE) {
		/**
		 * we read a message-sized buffer, now try to parse it
		 **/
		struct hotplug_msg *msg = (struct hotplug_msg *)read_buf;
		if (msg->magic == CONNECTION_MAGIC) {
			struct hotplug_msg reply = {0};
			if (!parse_hotplug_req(msg, &reply)) {
				kzfree(read_buf);
				read_buf = NULL;
				switch (reply.msg_type) {
				case REPLY: {
					size_t bytes_written = k_socket_write(sock,
									      sizeof(struct hotplug_msg),
									      &reply,
									      0);
					if (bytes_written == sizeof(struct hotplug_msg) &&
					    (! atomic64_read(&SHOULD_SHUTDOWN))) {
						/* do it all again */
						init_and_queue_work(work, worker, k_msg_server);
						/**
						 * return without closing the connection
						 **/
						up(&connection->s_lock);
						return;
					}
					break;
				}
				case COMPLETE: {
					/** client wishes to close the connection **/
					goto unlock_connection;
					break;
				}
				default: {
					printk(KERN_DEBUG "unexpected message type %d\n", reply.msg_type);
					goto unlock_connection;
					break;
				}
				}

			} /** parsed the message OK **/
		} /** CONNECTION_MAGIC **/
	} /** read_buf && read_size **/
unlock_connection:
	if (read_buf) {
		kzfree(read_buf);
	}
	up(&connection->s_lock);
close_out:
	spin_lock(&connections_lock);
	list_del_rcu(&(connection->l));
	spin_unlock(&connections_lock);
	synchronize_rcu();
	kfree(destroy_connection(connection));
	return;
}


/**
 * return a newly initialized connnection struct,
 * socket will either be bound and listening, or
 * accepted and connected, according to flags
 **/
struct connection *init_connection(struct connection *c, uint64_t flags, void *p)
{
	int ccode = 0;

	assert(c != NULL);
	assert(socket_name != NULL);
	assert(__FLAG_IS_SET(flags, SOCK_LISTEN) || __FLAG_IS_SET(flags, SOCK_CONNECTED));
	assert(! (__FLAG_IS_SET(flags, SOCK_LISTEN) && __FLAG_IS_SET(flags, SOCK_CONNECTED)));

	memset(c, 0x00, sizeof(struct connection));
	INIT_LIST_HEAD(&(c->l));
	sema_init(&(c->s_lock), 1);

/**
 * TODO: I should set the flags individually, or mask the flags param;
 * I'm assuming that listen and connect are the only two flags set in the flags param
 **/
	/**
	 * TODO: does sock_release free socket memory?
	 **/
	c->flags = flags;
	if (__FLAG_IS_SET(c->flags, SOCK_LISTEN)) {
		/**
		 * p is a pointer to a string holding the socket name
		 **/
		strncpy(c->path, (const char *)p, CONNECTION_PATH_MAX - 1);
		if((ccode = start_listener(c))) {
			ccode = -ENFILE;
			goto err_exit;
		}

		/**
		 * the socket is now bound and listening, we don't want to block
		 * here so schedule the accept to happen on a separate kernel thread.
		 * first, link it to the kernel sensor list of connections, then schedule
		 * it as work
		 **/

		spin_lock(&connections_lock);
		list_add_rcu(&(c->l), &connections);
		spin_unlock(&connections_lock);
		link_new_connection_work(c,
					 &connections,
					 k_accept,
					 "cpu hotplug accept");


	} else { /**
		  * new sock is accepted and a new
		  * connection is created, allocated elements are initialfized
		  * p is a pointer to a connected socket
		  **/
		struct socket *sock = p;
		printk(KERN_INFO "connected socket at %p\n", sock);
		/** now we need to read and write messages **/
		c->connected = sock;
		link_new_connection_work(c,
					 &connections,
					 k_msg_server,
					 "kcontrol read & write");
	}

	return c;

err_exit:

	if (c->connected) {
		c->connected = NULL;
	}
	return ERR_PTR(ccode);
}

static void awaken_accept_thread(void)
{
	struct sockaddr_un addr;
	struct socket *sock = NULL;
	size_t path_len, addr_len;
	int ccode = 0;

	sock_create_kern(&init_net, AF_UNIX, SOCK_STREAM, 0, &sock);
	if (!sock)
		return;


	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	path_len = strlen(socket_name);
	addr_len = sizeof(addr.sun_path) - 1;

	memcpy(addr.sun_path,
		   socket_name,
		   (path_len < addr_len) ? path_len : addr_len);
	ccode = kernel_connect(sock, (struct sockaddr *)&addr, sizeof(addr.sun_path), 0L);
	if (! ccode) {

		kernel_sock_shutdown(sock, SHUT_RDWR);
		sock_release(sock);
	}
	/**
	 * wait until the listener has exited
	 **/
	if (! down_interruptible(&listener.s_lock))
		up(&listener.s_lock);
	return;
}

static int unlink_sock_name(char *sock_name, char *lock_name)
{
	struct path name_path = {.mnt = 0};
	struct file *lock_file = NULL;
	struct file_lock l = {
		.fl_flags = FL_FLOCK,
		.fl_type = F_WRLCK,
	};
	int need_lock = 0;
	int ccode = kern_path(sock_name, LOOKUP_FOLLOW, &name_path);
	if (ccode) {
       /**
        * its not an error if we can't get the path, it probably means
        * the socket name does not need to be unlinked, perhaps it has not
        * been created yet.
	*
	* but, continue onward and try to get the lock file, so another instance
	* (in the future) will not unlink the sock name while we are using it.
	**/
		;
	}

	if (lock_name) {
		/**
		 * open the lock file, create it if necessary
		 **/
		lock_file = filp_open(lock_name, O_RDONLY | O_CREAT, S_IRUSR | S_IWUSR);
		if (IS_ERR(lock_file) || ! lock_file) {
			printk(KERN_DEBUG "error opening or creating the socket lock\n");
			ccode = -ENFILE;
			goto exit;
		}

		/**
		 * POSIX protocol says this lock will be released if the module
		 * crashes or exits
		 **/
		need_lock = vfs_lock_file(lock_file, F_SETLK, &l, NULL);
	}

	if (!need_lock && !ccode) {
		ccode = vfs_unlink(name_path.dentry->d_parent->d_inode,
						   name_path.dentry,
						   NULL);
	}
exit:
	return ccode;
}

static int cpu_hotplug_init(void)
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


static void cpu_hotplug_cleanup(void)
{
	printk(KERN_DEBUG "cpu hotplug demo unloading...\n");
	cpuhp_remove_state(CPUHP_AP_ONLINE_DYN);
}


int __init socket_interface_init(void)
{
	cpu_hotplug_init();
	unlink_sock_name(socket_name, lockfile_name);
	init_connection(&listener, SOCK_LISTEN, socket_name);
	return 0;
}

void __exit socket_interface_exit(void)
{
	atomic64_set(&SHOULD_SHUTDOWN, 1);
	awaken_accept_thread();
	unlink_sock_name(socket_name, NULL);
	cpu_hotplug_cleanup();
	return;
}

module_init(socket_interface_init);
module_exit(socket_interface_exit);


MODULE_LICENSE(_MODULE_LICENSE);
MODULE_AUTHOR(_MODULE_AUTHOR);
MODULE_DESCRIPTION(_MODULE_INFO);
