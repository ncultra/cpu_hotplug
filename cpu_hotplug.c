#include "cpu_hotplug.h"

atomic64_t SHOULD_SHUTDOWN = ATOMIC64_INIT(0);
EXPORT_SYMBOL(SHOULD_SHUTDOWN);

DEFINE_SPINLOCK(connections_lock);

struct list_head connections;

struct connection *listener = NULL;

EXPORT_SYMBOL(listener);

uint32_t protocol_version = 0x010000;
EXPORT_SYMBOL(protocol_version);

char *socket_name = "/var/run/cpu_hotplug.sock";
char *lockfile_name = "/var/run/cpu_hotplug.lock";
module_param(socket_name, charp, 0644);

static struct connection *reap_closed(void);
static void *destroy_connection(struct connection *c);

int (*_cpu_report_state)(int) = NULL;

struct sym_import sym_imports[] = {
	{.name = "cpu_report_state",
	 .addr = 0UL},
};

static int import_symbols(struct sym_import *imports, int size)
{
	for (int i = 0; i < size; i++) {
		imports[i].addr = kallsyms_lookup_name(imports[i].name);
		if (imports[i].addr == 0) {
			return -ENFILE;
		}
	}
	return 0;
}

static uint64_t find_private(struct sym_import *imports,
			    const char *name,
			    int size)
{
	for (int i = 0; i < size; i++) {
		if (! strncmp(name, imports[i].name, KSYM_NAME_LEN - 1)) {
			return imports[i].addr;
		}
	}
	return 0;
}

static void init_reply(struct hotplug_msg *req, struct hotplug_msg *rep)
{
	if (req && rep) {
		rep->magic = req->magic;
		rep->version = req->version;
		rep->msg_type = REPLY;
		rep->cpu = req->cpu;
		rep->action = req->action;
		rep->result = 0;
		memset(rep->possible_mask, 0x00, sizeof(rep->possible_mask));
		memset(rep->present_mask, 0x00, sizeof(rep->present_mask));
		memset(rep->online_mask, 0x00, sizeof(rep->online_mask));
		memset(rep->active_mask, 0x00, sizeof(rep->active_mask));
	}
	return;
}

static int handle_invalid(struct hotplug_msg *req, struct hotplug_msg *rep)
{
	init_reply(req, rep);
	rep->result = EINVAL;
	return 0;
}

static int handle_discover(struct hotplug_msg *req, struct hotplug_msg *rep)
{
	init_reply(req, rep);
	rep->result = OK;
	return 0;
}

int handle_unplug(struct hotplug_msg *req, struct hotplug_msg *rep)
{
	int ccode = OK;
	printk(KERN_DEBUG "%s: %s %u\n", __FILE__, __FUNCTION__, __LINE__);
	init_reply(req, rep);
	printk(KERN_DEBUG "%s: %s %u\n", __FILE__, __FUNCTION__, __LINE__);
	ccode = cpu_down(req->cpu);
	printk(KERN_DEBUG "%s: %s %u\n", __FILE__, __FUNCTION__, __LINE__);
	switch(ccode) {
	case OK:
	{
		rep->result = OK;
		break;
	}
	case -EBUSY:
	{
		rep->result = _EBUSY;
		break;
	}
	case -EPERM:
	{
		rep->result = _EPERM;
		break;
	}
	case -EINVAL:
	default:
	{
		rep->result = _EINVAL;
		break;
	}
	}
	return 0;
}

int handle_plug(struct hotplug_msg *req, struct hotplug_msg *rep)
{
	int ccode = OK;

	init_reply(req, rep);
	ccode = cpu_up(req->cpu);
	switch(ccode) {
	case OK:
	{
		rep->result = OK;
		break;
	}
	case -EBUSY:
	{
		rep->result = _EBUSY;
		break;
	}
	case -EPERM:
	{
		rep->result = _EPERM;
		break;
	}
	case -EINVAL:
	default:
	{
		rep->result = _EINVAL;
		break;
	}
	}
	return 0;
}

/**
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

int handle_get_cur_state(struct hotplug_msg *req, struct hotplug_msg *rep)
{
	init_reply(req, rep);
	rep->current_state = (uint32_t)_cpu_report_state(req->cpu);
	return 0;
}

int handle_set_target_state(struct hotplug_msg *req, struct hotplug_msg *rep)
{
	init_reply(req, rep);
	rep->result = NOT_IMPL;
	return 0;
}

dispatch_t dispatch_table[] = {
	handle_invalid,
	handle_discover,
	handle_unplug,
	handle_plug,
	handle_get_cur_state,
	handle_set_target_state,
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

	if (!check_magic(request) || !maj_ver_compat(request)) {
		return -EINVAL;
	}

	if (request->msg_type == REQUEST &&
	    request->action > ZERO &&
	    request->action < LAST) {
		printk(KERN_DEBUG "%s: %s %u request header looks good, calling into dispatch table[%d]\n",
		       __FILE__, __FUNCTION__, __LINE__,
		       request->action);
		return dispatch_table[request->action](request, response);
	}
	else {
		printk(KERN_DEBUG "%s: %s %u request header looks good but action %d is invalid\n",
		       __FILE__, __FUNCTION__, __LINE__,
			request->action);
		return dispatch_table[0](request, response);
	}

	return -EINVAL;
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
	printk(KERN_DEBUG "%s: %s %u k_socket_read sock %p, num bytes to read %ld," \
         " in buf %p, flags %x\n",
         __FILE__, __FUNCTION__, __LINE__,
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
  printk(KERN_DEBUG "%s: %s %u recvmsg returned %ld bytes\n",
         __FILE__, __FUNCTION__, __LINE__,
         bytes_read);
	*actual_size = bytes_read;
  printk(KERN_DEBUG "%s: %s %u %ld bytes stored in  buf %p\n",
         __FILE__, __FUNCTION__, __LINE__,
         *actual_size,
         buf);
	if (max_size != *actual_size) {
		buf = krealloc(buf, bytes_read, GFP_KERNEL);
    printk(KERN_DEBUG "%s: %s %u buf: %p\n",
           __FILE__, __FUNCTION__, __LINE__,
           buf);
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

static void k_accept(struct kthread_work *work)
{
	int ccode = 0;
	bool is_queued = 0;
	struct connection *connection = NULL, *new_connection = NULL;
	struct socket *newsock = NULL;
	struct kthread_worker *worker = NULL;
	if (!work) {
		printk(KERN_DEBUG "invalid work passed to k_accept\n");
		goto close_out_quit;
	}
	connection = container_of(work, struct connection, work);
	worker = connection->worker;
	printk(KERN_DEBUG "%s: %s %u\n", __FILE__, __FUNCTION__, __LINE__);
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
		/**
		 * first try to reap a closed connection
		 **/
		spin_lock(&connections_lock);
		new_connection = reap_closed();
		spin_unlock(&connections_lock);
		if (new_connection != NULL) {
			printk(KERN_DEBUG "%s: %s %u reaped closed connection %p\n",
			       __FILE__, __FUNCTION__, __LINE__,
				new_connection);
			destroy_connection(new_connection);
		}
		else {
			new_connection = kzalloc(sizeof(struct connection), GFP_KERNEL);
		}

		if (new_connection) {
			printk(KERN_DEBUG "%s: %s %u new connection (created upon accept): %p\n",
			       __FILE__, __FUNCTION__, __LINE__,
			       new_connection);
			/**
			 * init_connection will create a kernel thread for the new connection
			 **/
			init_connection(new_connection, SOCK_CONNECTED, newsock);
		} else {
			atomic64_set(&SHOULD_SHUTDOWN, 1);
			goto close_out_quit;
		}
	}
close_out_reschedule:
	if (! atomic64_read(&SHOULD_SHUTDOWN)) {
		kthread_init_work(work, k_accept);
		is_queued = kthread_queue_work(worker, work);
		printk(KERN_DEBUG "%s: %s %u kthread_queue_work() returned %d\n",
		       __FILE__, __FUNCTION__, __LINE__,
		       is_queued);
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
		printk(KERN_DEBUG "%s: %s %u error creating listening socket\n",
		       __FILE__, __FUNCTION__, __LINE__);
		c->connected = NULL;
		goto err_exit;
	}
	c->connected = sock;
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	memcpy(addr.sun_path, &c->path[0], sizeof(addr.sun_path));

	/* sizeof(address) - 1 is necessary to ensure correct null-termination */
	if (kernel_bind(sock, (struct sockaddr *)&addr, sizeof(addr) -1)) {
		printk(KERN_DEBUG "%s: %s %u error binding socket to path\n",
		       __FILE__, __FUNCTION__, __LINE__);
		goto err_release;

	}
/* see /usr/include/net/tcp_states.h */
	if (kernel_listen(sock, TCP_LISTEN)) {
		printk(KERN_DEBUG "%s: %s %u error socket listening\n",
		       __FILE__, __FUNCTION__, __LINE__);
		kernel_sock_shutdown(sock, RCV_SHUTDOWN | SEND_SHUTDOWN);
		goto err_release;
	}

	return 0;
err_release:
	sock_release(sock);
err_exit:
	c->connected = NULL;
	printk(KERN_DEBUG "%s: %s %u start_listener() returning -ENFILE\n",
	       __FILE__, __FUNCTION__, __LINE__);
	return -ENFILE;
}

static void link_new_connection_work(struct connection *c,
                                     struct list_head *l)
{

	if (! atomic64_read(&SHOULD_SHUTDOWN)) {
		spin_lock(&connections_lock);
		list_add_rcu(&(c->l), l);
		spin_unlock(&connections_lock);
		__SET_FLAG(c->flags, SOCK_HAS_WORK);
	}
}

/**
 * tear down the connection but don't free the connection
 * memory. do free resources, struct sock.
 **/
static void *destroy_connection(struct connection *c)
{
	printk(KERN_DEBUG "%s: %s %u\n", __FILE__, __FUNCTION__, __LINE__);
	if (down_interruptible(&c->s_lock))
		return NULL;
	if (c->worker) {
		/**
		 * flushes work, frees worker
		 **/
		kthread_destroy_worker(c->worker);
		c->worker = NULL;
	}
	if (c->connected) {
		kernel_sock_shutdown(c->connected, SHUT_RDWR);
		sock_release(c->connected);
		c->connected = NULL;
	}
	memset(c, 0x00, sizeof(*c));
	return c;
}

/**
 * must be called with connections_lock held
 **/
static struct connection *reap_closed(void)
{
	struct connection *cursor;
	list_for_each_entry_rcu(cursor, &connections, l) {
		if (cursor && __FLAG_IS_SET(CONNECTION_CLOSED, cursor->flags)) {
			list_del_rcu(&cursor->l);
			return cursor;
		}

	}
	return NULL;
}


static int __attribute__((used)) reap_and_destroy(void)
{
	struct connection *dead;
	int count = 0;
	spin_lock(&connections_lock);
	dead = reap_closed();
	while (dead != NULL) {
		destroy_connection(dead);
		kzfree(dead);
		count++;
		dead = reap_closed();
	}
	spin_unlock(&connections_lock);
	return count;
}


/**
 * dispatched from a kernel thread, has a connected socket
 * read and write cpu hotplug messages. If encountering an error, close the socket.
 * if no error, re-schedule the kernel thread to run again.
 **/
static void k_msg_server(struct kthread_work *work)
{
	int ccode = 0;
	bool is_queued = 0;
	size_t read_size = 0;
	uint8_t * read_buf = NULL;
	struct connection *c = NULL;
	struct socket *sock = NULL;
	struct kthread_worker *worker = NULL;

	if (!work) {
		printk(KERN_DEBUG "message server: invalid work\n");
		goto close_out;
	}

	c = container_of(work, struct connection, work);
	worker = c->worker;
	sock = c->connected;
	ccode = down_interruptible(&c->s_lock);
	if (ccode) {
		printk(KERN_DEBUG "message server: unable to down connection semaphore\n");
		return;
	}
	if (! (__FLAG_IS_SET(c->flags, SOCK_CONNECTED) &&
	       __FLAG_IS_SET(c->flags, SOCK_HAS_WORK))) {
		printk(KERN_DEBUG "message server: invalid connection flags\n");
		goto close_out;
	}

	printk(KERN_DEBUG "%s: %s %u about to read connection %p\n",
	       __FILE__, __FUNCTION__, __LINE__,
	       c);

	read_buf = read_alloc_buf(sock, CONNECTION_MAX_MESSAGE, &read_size);
	if (read_buf && read_size == CONNECTION_MAX_MESSAGE) {
		/**
		 * we read a message-sized buffer, now try to parse it
		 **/
		struct hotplug_msg *msg = (struct hotplug_msg *)read_buf;

		printk(KERN_DEBUG "%s: %s %u read %ld bytes from connection %p into buffer %p\n",
		       __FILE__, __FUNCTION__, __LINE__,
		       read_size,
		       c,
		       read_buf);

		printk(KERN_DEBUG "%s: %s %u %x %x\n",
		       __FILE__, __FUNCTION__, __LINE__,
		       msg->magic,
		       CONNECTION_MAGIC);
		if (msg->magic == CONNECTION_MAGIC) {
			struct hotplug_msg reply = {0};
			int ccode;
			if (! (ccode = parse_hotplug_req(msg, &reply))) {
				/**
				 * we have succesfully created a response, so we can free
				 * the read_buf now.
				 **/
				printk(KERN_DEBUG "%s: %s %u parse_hotplug_req returned %d\n",
				       __FILE__, __FUNCTION__, __LINE__,
				       ccode);
				kzfree(read_buf);
				read_buf = NULL;
				switch (reply.msg_type) {
				case REPLY: {
					size_t bytes_written = 0;

					printk(KERN_DEBUG "%s: %s %u\n", __FILE__, __FUNCTION__, __LINE__);
					bytes_written = k_socket_write(sock,
								       sizeof(struct hotplug_msg),
								       &reply,
								       0);
					if (bytes_written == sizeof(struct hotplug_msg) &&
					    (! atomic64_read(&SHOULD_SHUTDOWN))) {
						/* do it all again */
						/**
						 * return without closing the connection
						 **/
						is_queued =kthread_queue_work(worker, work);
						up(&c->s_lock);
						printk(KERN_DEBUG "%s: %s %u kthread_queue_work() returned %d\n",
						       __FILE__, __FUNCTION__, __LINE__,
						       is_queued);
						return;
					}
					break;
				}
				case COMPLETE: {
					/** client wishes to close the connection **/
					goto close_out;
					break;
				}
				default: {
					printk(KERN_DEBUG "unexpected message type %d\n", reply.msg_type);
					goto close_out;
					break;
				}
				}
			} /** parsed the message OK **/
		} /** CONNECTION_MAGIC **/
	} /** read_buf && read_size **/
close_out:
	if (read_buf) {
		kzfree(read_buf);
	}
	mark_conn_closed(c);
	up(&c->s_lock);
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
	bool is_queued = 0;

	assert(c != NULL);
	assert(socket_name != NULL);
	assert(__FLAG_IS_SET(flags, SOCK_LISTEN) || __FLAG_IS_SET(flags, SOCK_CONNECTED));
	assert(! (__FLAG_IS_SET(flags, SOCK_LISTEN) && __FLAG_IS_SET(flags, SOCK_CONNECTED)));

	printk(KERN_DEBUG "%s: %s %u initializing new connection %p %s\n",
	       __FILE__, __FUNCTION__, __LINE__,
	       c,
	       (char *)p);
	memset(c, 0x00, sizeof(struct connection));
	INIT_LIST_HEAD(&(c->l));
	sema_init(&(c->s_lock), 1);

/**
 * TODO: I should set the flags individually, or mask the flags param;
 * I'm assuming that listen and connect are the only two flags set in the flags param
 **/
	c->flags = flags;
	if (__FLAG_IS_SET(c->flags, SOCK_LISTEN)) {


		/**
		 * p is a pointer to a string holding the socket name
		 **/
		printk(KERN_DEBUG "%s: %s %u initializing the listener, connection: %p %s\n",
		       __FILE__, __FUNCTION__, __LINE__,
		       c, (char *)p);
		c->worker = kthread_create_worker(0, "listener");
		if (c->worker == ERR_PTR(-ENOMEM)) {
			c->worker = NULL;
			ccode = -ENOMEM;
			goto err_exit;
		}

		printk(KERN_DEBUG "%s: %s %u running server for connection %p\n",
		       __FILE__, __FUNCTION__, __LINE__,
		       c);


		strncpy(c->path, (const char *)p, CONNECTION_PATH_MAX - 1);
		/**
		 * start_listener creates the socket and calls listen
		 **/
		if((ccode = start_listener(c))) {
			ccode = -ENFILE;
			goto err_exit;
		}

		link_new_connection_work(c, &connections);
		/**
		 * the socket is now bound and listening, we don't want to block
		 * here so schedule the accept to happen on a separate kernel thread.
		 **/
		kthread_init_work(&c->work, k_accept);
		is_queued = kthread_queue_work(c->worker, &c->work);
		printk(KERN_DEBUG "%s: %s %u kthread_queue_work() returned %d\n",
		       __FILE__, __FUNCTION__, __LINE__,
			is_queued);
	} else {
		/**
		 * new sock is accepted and a new
		 * connection is created, allocated elements are initialized
		 * p is a pointer to a connected socket
		 **/
		/** now we need to read and write messages **/
		c->connected = (struct socket *)p;
		printk(KERN_DEBUG "%s: %s %u initializing the new session connection %p , using socket %p\n",
		       __FILE__, __FUNCTION__, __LINE__,
		       c, c->connected);

		c->worker = kthread_create_worker(0, "server thread");
		if (c->worker == ERR_PTR(-ENOMEM)) {
			c->worker = NULL;
			ccode = -ENOMEM;
			goto err_exit;
		}
		link_new_connection_work(c, &connections);
		kthread_init_work(&c->work, k_msg_server);
		is_queued = kthread_queue_work(c->worker, &c->work);
		printk(KERN_DEBUG "%s: %s %u kthread_queue_work() returned %d\n",
		       __FILE__, __FUNCTION__, __LINE__,
			is_queued);
	}
	return c;

err_exit:
	if (c->connected) {
		c->connected = NULL;
	}
	if (c->worker) {
		kthread_destroy_worker(c->worker);
		c->worker = NULL;
	}
	return ERR_PTR(ccode);
}

static void __attribute__((used)) awaken_accept_thread(void)
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
	if (! down_interruptible(&listener->s_lock))
	{
		up(&listener->s_lock);
	}

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

int unlink_file(char *filename)
{
	int ccode = 0;

	struct path name_path = {.mnt = 0};
	if (!filename) {
		return -EINVAL;
	}

	ccode = kern_path(filename, LOOKUP_FOLLOW, &name_path);
	if (!ccode) {
		ccode = vfs_unlink(name_path.dentry->d_parent->d_inode,
				   name_path.dentry,
				   NULL);
	}
	return ccode;
}


static int cpu_hotplug_init(void)
{
	int ccode = 0;
	printk(KERN_DEBUG "cpu hotplug demo module\n");
	ccode = cpuhp_setup_state_nocalls(CPUHP_AP_ONLINE_DYN,
					  "x86/demo:online",
					  my_cpu_online,
					  my_cpu_going_offline);

	printk(KERN_DEBUG "cpuhp_setup_state returned %d\n", ccode);
	return 0;
}


static void cpu_hotplug_cleanup(void)
{
	printk(KERN_DEBUG "cpu hotplug demo unloading...\n");
	cpuhp_remove_state_nocalls(CPUHP_AP_ONLINE_DYN);
}


int __init socket_interface_init(void)
{
	int ccode = import_symbols(sym_imports, SIZE_IMPORTS);
	printk(KERN_DEBUG "%s: %s %u import_symbols returned %d\n",
	       __FILE__, __FUNCTION__, __LINE__,
		ccode);
	if (ccode) {
		return ccode;
	}

	_cpu_report_state = (int (*)(int))find_private(sym_imports,
					 "cpu_report_state",
					 SIZE_IMPORTS);
	printk(KERN_DEBUG "%s: %s %u address of cpu_report_state %016llx\n",
	       __FILE__, __FUNCTION__, __LINE__,
	       (uint64_t)_cpu_report_state);

	if (_cpu_report_state == NULL) {
		return -ENFILE;
	}

	INIT_LIST_HEAD_RCU(&connections);
	atomic64_set(&SHOULD_SHUTDOWN, 0);
	cpu_hotplug_init();
	unlink_sock_name(socket_name, lockfile_name);
	listener = kzalloc(sizeof(struct connection), GFP_KERNEL);
	if (! listener)
	{
		printk(KERN_DEBUG "%s: %s %u allocation failed - returning -ENOMEM\n",
		       __FILE__, __FUNCTION__, __LINE__);
		return -ENOMEM;
	}

	printk(KERN_DEBUG "%s: %s %u calling init_connection with listening connection %p\n",
	       __FILE__, __FUNCTION__, __LINE__,
	       listener);
	init_connection(listener, SOCK_LISTEN, socket_name);
	return 0;
}



/**
 * the __exit routine is called with preemption disabled and will crash if it makes any
 * calls capable of sleeping. There is more we should do here, but unloading is mostly
 * useful for the development phase.
 **/
void __exit socket_interface_exit(void)
{
	struct connection *c = NULL;
	atomic64_set(&SHOULD_SHUTDOWN, 1);

	/**
	 * go through list of connections, destroy each connection
	 **/
	unlink_sock_name(socket_name, lockfile_name);
	spin_lock(&connections_lock);
	c = list_first_or_null_rcu(&connections, struct connection, l);
	while (c != NULL) {
		list_del_rcu(&c->l);
		/**
		 * don't call destroy_connection() because it calls flush_work()
		 **/
		kzfree(c);
		c = list_first_or_null_rcu(&connections, struct connection, l);
	}
	spin_unlock(&connections_lock);

	unlink_file(lockfile_name);
	cpu_hotplug_cleanup();
	return;
}

module_init(socket_interface_init);
module_exit(socket_interface_exit);


MODULE_LICENSE(_MODULE_LICENSE);
MODULE_AUTHOR(_MODULE_AUTHOR);
MODULE_DESCRIPTION(_MODULE_INFO);
