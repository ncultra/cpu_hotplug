#include "cpu_hotplug.h"

atomic64_t SHOULD_SHUTDOWN = ATOMIC64_INIT(0);

DEFINE_SPINLOCK(connections_lock);
DEFINE_SPINLOCK(bitmap_lock);
struct list_head connections;

struct connection *listener = NULL;

uint32_t protocol_version = 0x010000;

char *socket_name = "/var/run/cpu_hotplug.sock";
module_param(socket_name, charp, 0644);

char *lockfile_name = "/var/run/cpu_hotplug.lock";
module_param(lockfile_name, charp, 0644);

static struct file_lock f_lock = {
	.fl_flags = FL_FLOCK,
	.fl_type = F_WRLCK
};

static struct file *f_lock_file = NULL;

static struct file *open_lock_file(char *lock_name);
static int close_lock_file(struct file *f);
static int lock_file(struct file *f, struct file_lock *l);
static int unlock_file(struct file *f, struct file_lock *l);

static struct connection *reap_closed(void);
static void *destroy_connection(struct connection *c);
static int32_t  read_cpu_state_file(int cpu);
static int write_cpu_target_file(int cpu, int target);
static int __attribute__((used)) copy_cpu_bitmask(struct cpumask *dst, struct cpumask *src);

int (*_cpu_report_state)(int) = NULL;

struct sym_import sym_imports[] = {
	{.name = "cpu_report_state",
	 .addr = 0UL},
};


/******************************************************************************/
/**
 * @brief: import private symbols from the linux kernel
 *
 * @param[in]  imports - pointer to array of struct sym_imports
 * @param[in]  size - number of elements in imports
 * @returns    zero if all the symbols were imported, -ENFILE if at least
 *             one of the symbols was not imported.
 *
 * @note: before being callable, each imported symbol needs a function pointer
 *        initialized to the addr element.
 *
 ******************************************************************************/

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

/******************************************************************************/
/**
 * @brief: find the address of a specific private symbol that has previously
 *         been imported into the struct sym_import array.
 *
 * @param[in]  imports - pointer to array of struct sym_imports
 * @param[in]  name - the name of the symbol to find
 * @param[in]  size - the number of array elements to search
 * @returns    address of symbol of found, 0 if not found,
 *             -EINVAL if invalid input
 *
 ******************************************************************************/

static uint64_t find_private(struct sym_import *imports,
			    const char *name,
			    int size)
{
	if (imports == NULL ||
	    (sizeof(*imports) / sizeof(struct sym_import) < size)) {
		return -EINVAL;
	}

	for (int i = 0; i < size; i++) {
		if (! strncmp(name, imports[i].name, KSYM_NAME_LEN - 1)) {
			return imports[i].addr;
		}
	}
	return 0;
}

/******************************************************************************/
/**
 * @brief: use a request message to initialize a reply message
 *
 * @param[in]     req - pointer to an initialized request message
 * @param[in,out] rep - pointer to a reply message
 * @returns void
 *
 * @note: essentially a structure copy with msg_type set to REPLY
 *
 ******************************************************************************/

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

/******************************************************************************/
/**
 * @brief: handle an invalid message
 *
 * @param[in]      req - pointer to an initialized request message
 * @param[in, out] rep - pointer to a reply message
 * @returns zero for success
 *
 * @note: If a message has a valid header, but an invalid type, it will get
 *        handled here. The reply will have a result code of EINVAL, and
 *        will be sent to the client.
 *
 ******************************************************************************/

static int handle_invalid(struct hotplug_msg *req, struct hotplug_msg *rep)
{
	init_reply(req, rep);
	rep->result = EINVAL;
	return 0;
}


/******************************************************************************/
/**
 * @brief: handle a DISCOVER request
 *
 * @param[in]      req - pointer to an initialized DISCOVER request
 * @param[in, out] rep - pointer to a reply message
 * @returns zero for success
 *
 * @note: the DISCOVER message is the way for a client or driver to get basic
 *        information about the server or device, as well as to confirm
 *        the message medium is functional.
 *
 ******************************************************************************/

static int handle_discover(struct hotplug_msg *req, struct hotplug_msg *rep)
{
	init_reply(req, rep);
	rep->result = OK;
	return 0;
}


/******************************************************************************/
/**
 * @brief: handle an UNPLUG request
 *
 * @param[in]      req - pointer to an initialized UNPLUG message
 * @param[in, out] rep - pointer to a reply message
 * @returns zero for success.
 *
 * @note: Causes the server or device to unplug a cpu. The reply message will contain
 *        a result of OK if the cpu was unplugged,  _EBUSY, _EPERM, or _EINVAL
 *        if the unplug action is not successful.
 *
 ******************************************************************************/

static int handle_unplug(struct hotplug_msg *req, struct hotplug_msg *rep)
{
	int ccode = OK;
	init_reply(req, rep);
	ccode = cpu_down(req->cpu);
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


/******************************************************************************/
/**
 * @brief: handle a PLUG request
 *
 * @param[in]      req - pointer to an initialized PLUG message
 * @param[in, out] rep - pointer to a reply message
 * @returns zero for success.
 *
 * @note: Causes the server or device to plug in a cpu. The reply message will contain
 *        a result of OK if the cpu was plugged in,  _EBUSY, _EPERM, or _EINVAL
 *        if the plug action is not successful.
 *
 ******************************************************************************/

static int handle_plug(struct hotplug_msg *req, struct hotplug_msg *rep)
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

/******************************************************************************/
/**
 * @brief: handle a GET_BOOT_STATE request
 *
 * @param[in]      req - pointer to an initialized GET_BOOT_STATE message
 * @param[in, out] rep - pointer to a reply message
 * @returns zero for success.
 *
 * @note: retrieves the functional (not hot-plug) state of the cpu:
 *        online, preparing, dead, frozen, post dead, broken
 *
 ******************************************************************************/

static int handle_get_boot_state(struct hotplug_msg *req, struct hotplug_msg *rep)
{
	init_reply(req, rep);
	rep->current_state = (uint32_t)_cpu_report_state(req->cpu);
	return 0;
}

/******************************************************************************/
/**
 * @brief: handle a GET_CURRENT_STATE request
 *
 * @param[in]      req - pointer to an initialized GET_CURRENT_STATE message
 * @param[in, out] rep - pointer to a reply message
 * @returns zero for success.
 *
 * @note: retrieves the current hot-plug state of a cpu. This will be one the
 *        states enumerated in <linux/cpuhotplug.h>
 *
 *        (Reads the sysfs state file.)
 *
 ******************************************************************************/

static int handle_get_cur_state(struct hotplug_msg *req, struct hotplug_msg *rep)
{
	int32_t ccode = 0;
	init_reply(req, rep);
	ccode = read_cpu_state_file(req->cpu);
	if (ccode < 0) {
		switch(ccode) {
		case -ENOMEM:
			rep->result = _ENOMEM;
			break;
		case -EBADF:
			rep->result = _EBADF;
			break;
		case -ERANGE:
			rep->result = _ERANGE;
			break;
		default:
			rep->result = _EINVAL;
			break;
		}
	}
	else {
		rep->result = 0;
		rep->current_state = ccode;
	}
	return 0;
}

/******************************************************************************/
/**
 * @brief: handle a SET_TARGET_STATE request
 *
 * @param[in]      req - pointer to an initialized SET_TARGET_STATE message
 * @param[in, out] rep - pointer to a reply message
 * @returns zero for success.
 *
 * @note: writes a new target state value for the cpu. This will be one the
 *        states enumerated in <linux/cpuhotplug.h>.
 *
 *        This will cause a state transition to occur. For example writing '0'
 *        will unplug the cpu. (writes to the sysfs target file.)
 *
 ******************************************************************************/

static int handle_set_target_state(struct hotplug_msg *req, struct hotplug_msg *rep)
{
	int ccode = 0;

	init_reply(req, rep);
	ccode = write_cpu_target_file(req->cpu, req->target_state);
	if (ccode < 0) {
		switch(ccode) {
		case -EBADF:
			rep->result = _EBADF;
			break;
		case -ERANGE:
			rep->result = _ERANGE;
			break;
		default:
			rep->result = _EINVAL;
			break;
		}
	}
	else {
		rep->result = 0;
	}
	return 0;
}

/******************************************************************************/
/**
 * @brief: handle a request to copy the kernel's cpu state bitmasks
 *
 * @param[in]  req - pointer to a request message
 * @param[out] rep - pointer to the response message
 * @returns OK (0) upon success, non-zero otherwise.
 *
 * @note: prints a debug message if nr_cpu_ids is greater than MAX_NR_CPUS (512)
 *
 * @note: returns the kernel's count of CPU ids in reply->cpu field.
 *
 ******************************************************************************/

static int handle_get_cpu_bitmasks(struct hotplug_msg *req, struct hotplug_msg *rep)
{
	int ccode = OK;
	unsigned long flags = 0UL;
	struct cpumask *dst = NULL, *src = NULL;

	init_reply(req, rep);
	spin_lock_irqsave(&bitmap_lock, flags);
	dst = (struct cpumask *)rep->possible_mask;
	src = (struct cpumask *)&__cpu_possible_mask;

	/**
	 * only store the result once, for the possible mask.
	 * If any result is -ERANGE, it will be the possible mask.
	 * The result for the remaining masks will be the same.
	 **/
	ccode = copy_cpu_bitmask(dst, src);

	dst = (struct cpumask *)rep->present_mask;
	src = (struct cpumask *)&__cpu_present_mask;
	copy_cpu_bitmask(dst, src);

	dst = (struct cpumask *)rep->online_mask;
	src = (struct cpumask *)&__cpu_online_mask;
	copy_cpu_bitmask(dst, src);

	dst = (struct cpumask *)rep->active_mask;
	src = (struct cpumask *)&__cpu_active_mask;
	copy_cpu_bitmask(dst, src);

	spin_unlock_irqrestore(&bitmap_lock, flags);

	/**
	 * store the number of of cpu IDs in the cpu field of the reply
	 **/
	rep->cpu = nr_cpu_ids;

	if (ccode == -ERANGE) {
		printk(KERN_DEBUG "%s: %s %u Copy bitmask range overflow\n",
		       __FILE__, __FUNCTION__, __LINE__);
		ccode = OK;
	}

	return ccode;
}


dispatch_t dispatch_table[] = {
	handle_invalid,
	handle_discover,
	handle_unplug,
	handle_plug,
	handle_get_boot_state,
	handle_get_cur_state,
	handle_set_target_state,
	handle_get_cpu_bitmasks,
	handle_invalid
};

/**
 * @brief: callback prior to cpu coming online
 **/
static int my_cpu_online(unsigned int cpu)
{
	int ccode = 0;
	return ccode;
}

/**
 * @brief: callback prior to cpu going offline
 **/
static int my_cpu_going_offline(unsigned int cpu)
{
	int ccode = 0;
	return ccode;
}

/******************************************************************************/
/**
 * @brief: parse an incoming hotplug message, dispatch the message,
 *         initialize the reply
 *
 * @param[in]      request - pointer to the request message
 * @param[in, out] response - pointer to a response structure
 * @returns OK upon success, negative otherwise
 *
 * @note: checks the message header for a magic number, major version
 *        and supported action before calling into the dispatch table.
 *        The dispatch table will call the message handler and return
 *        an initialized response.
 *
 ******************************************************************************/

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
		return dispatch_table[request->action](request, response);
	}
	else {
		return dispatch_table[0](request, response);
	}

	return -EINVAL;
}

/******************************************************************************/
/**
 * @brief: read from a kernel socket
 *
 * @param[in] sock - pointer to a struct socket
 * @param[in] size - the number of bytes to attempt to read
 * @param[in] in - pointer to buffer which will receive the bytes
 * @param[in] flags kernel flags, zero in this module
 * @returns number of bytes read, or negative upon error
 *
 ******************************************************************************/

size_t k_socket_read(struct socket *sock,
                     size_t size,
                     void *in,
                     unsigned int flags)
{

	size_t res = 0;
	struct msghdr msg = {.msg_flags = flags};
	struct kvec iov = {.iov_base = in, .iov_len = size};
again:
	res = kernel_recvmsg(sock, &msg, &iov, 1, size, flags);
	if (res == -EAGAIN)
		goto again;

	return res;
}


/******************************************************************************/
/**
 * @brief: allocate a buffer and read bytes from a socket into the buffer,
 *         return the allocated buffer filled with bytes read from the socket.
 *
 * @param[in]      sock - pointer to a struct socket
 * @param[in]      max_size - the amount of memory to allocate for the buffer, and
 *                 the maximum number of bytes to read into the buffer.
 * @param[in, out] actual_size - the number of bytes read into the buffer.
 * @returns pointer to the allocated buffer containing read bytes, or NULL
 *
 * @note:
 *
 ******************************************************************************/

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
		return buf;
	}

	bytes_read = k_socket_read(sock, max_size, buf, 0);
	if (bytes_read <= 0) {
		if (bytes_read < 0) {
			printk(KERN_DEBUG "recvmsg returned error %ld\n", bytes_read);
		}
		else if (bytes_read == 0) {
			;
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

/******************************************************************************/
/**
 * @brief: Write a buffer to a connected socket
 *
 * @param[in] socket - pointer to a struct socket
 * @param[in] size - the number of bytes to write
 * @param[in] out - buffer containing bytes to write
 * @param[in] flags - always zero in this module
 * @returns the number of bytes written
 *
 * @note:
 *
 ******************************************************************************/

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

/******************************************************************************/
/**
 * @brief: kernel thread that accepts new connections.
 *
 * @param[in] work - pointer to a struct kthread_work
 * @returns void
 *
 * @note: for each new connection, calls a function that spawns that connection
 *        as a new kernel thread.
 *
 ******************************************************************************/

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
			destroy_connection(new_connection);
		}
		else {
			new_connection = kzalloc(sizeof(struct connection), GFP_KERNEL);
		}

		if (new_connection) {
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
	}
close_out_quit:
	up(&connection->s_lock);
	return;
}


/******************************************************************************/
/**
 * @brief: creates a socket, binds it, and listens for new connections with it
 *
 * @param[in] c - pointer to a struct connection
 * @returns OK (0) or -ENFILE
 *
 * @note:
 *
 ******************************************************************************/

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

	return OK;
err_release:
	sock_release(sock);
err_exit:
	c->connected = NULL;
	printk(KERN_DEBUG "%s: %s %u start_listener() returning -ENFILE\n",
	       __FILE__, __FUNCTION__, __LINE__);
	return -ENFILE;
}

/******************************************************************************/
/**
 * @brief: links an initialized connection to the global list, sets flags to
 *         indicate that the connection has work for a kernel thread.
 *
 * @param[in] c - pointer to an initialized struct connection
 * @param[in] l - pointer to struct list_head
 * @returns void
 *
 * @note: connection is linked into the list head
 *
 ******************************************************************************/

static void link_new_connection_work(struct connection *c,
                                     struct list_head *l)
{

	if (! atomic64_read(&SHOULD_SHUTDOWN)) {
		spin_lock(&connections_lock);
		list_add(&(c->l), l);
		spin_unlock(&connections_lock);
		__SET_FLAG(c->flags, SOCK_HAS_WORK);
	}
}

/**
 * tear down the connection but don't free the connection
 * memory. do free resources, struct sock.
 **/
/******************************************************************************/
/**
 * @brief: stops and frees the resources used by the connection, including
 *         kernel thread and socket, zeroes connection memory.
 *
 * @param[in] c - pointer to a struct connection
 * @returns a pointer to the zeroed connection memory
 *
 * @note: does not free the struct connection; this allows it to work with both
 *        statically and heap-allocated struct connections.
 *
 ******************************************************************************/

static void *destroy_connection(struct connection *c)
{
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

 **/
/******************************************************************************/
/**
 * @brief: traverse the connection list looking for closed connections. If found,
 *         unlink and return the connection for recycling or destruction.
 *
 * @param[in] void
 * @returns pointer to a recycled struct connection, or NULL
 *
 * @note: must be called with connections_lock held
 *
 ******************************************************************************/

static struct connection *reap_closed(void)
{
	struct connection *cursor;
	list_for_each_entry(cursor, &connections, l) {
		if (cursor && __FLAG_IS_SET(CONNECTION_CLOSED, cursor->flags)) {
			list_del(&cursor->l);
			return cursor;
		}

	}
	return NULL;
}


/******************************************************************************/
/**
 * @brief: reap and destroy closed connections
 *
 * @param[in] void
 * @returns the number of connections reaped and destroyed
 *
 * @note:
 *
 ******************************************************************************/

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

/******************************************************************************/
/**
 * @brief: kernel thread that reads, parses, and writes hotplug messages
 *
 * @param[in] work - pointer to struct kthread_work, which is embedded within
 *            a struct connection
 * @returns void
 *
 * @note: each new connection spawns a thread running this server. The threads
 *        runs until the client closes the connection, stops responding,
 *        or sends an invalid message.
 *
 ******************************************************************************/

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

	read_buf = read_alloc_buf(sock, CONNECTION_MAX_MESSAGE, &read_size);
	if (read_buf && read_size == CONNECTION_MAX_MESSAGE) {
		/**
		 * we read a message-sized buffer, now try to parse it
		 **/
		struct hotplug_msg *msg = (struct hotplug_msg *)read_buf;

		if (msg->magic == CONNECTION_MAGIC) {
			struct hotplug_msg reply = {0};
			int ccode;
			if (! (ccode = parse_hotplug_req(msg, &reply))) {
				/**
				 * we have succesfully created a response, so we can free
				 * the read_buf now.
				 **/
				kzfree(read_buf);
				read_buf = NULL;
				switch (reply.msg_type) {
				case REPLY: {
					size_t bytes_written = 0;

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

/******************************************************************************/
/**
 * @brief: initializes a new connection. connections are either (1) listening
 *         and accpeting new connections, or (2) a new accepted connection with
 *         a connected socket.
 *
 * @param[in] c - pointer to a new connection
 * @param[in] flags - must be SOCK_LISTEN or SOCK_CONNECTED, but not both
 * @param[in] p - pointer to either a string with the name of the listening
 *            socket, or a pointer to a connected socket, depending upon the
 *            flags.
 * @returns pointer to a struct connection, or ERR_PTR(-ENOMEM | -ENFILE | ccode)
 *
 * @note: void *p always identifies the socket element. If the SOCK_LISTEN flag
 *        is set, (char *)p is the name of the file the socket will be bound to.
 *        If the SOCK_CONNECTED flag is set, (struct socket *)p is a connected
 *        socket created by a call to accept().
 *
 ******************************************************************************/

struct connection *init_connection(struct connection *c, uint64_t flags, void *p)
{
	int ccode = 0;
	bool is_queued = 0;

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
	c->flags = flags;
	if (__FLAG_IS_SET(c->flags, SOCK_LISTEN)) {
		/**
		 * p is a pointer to a string holding the socket name
		 **/
		c->worker = kthread_create_worker(0, "listener");
		if (c->worker == ERR_PTR(-ENOMEM)) {
			c->worker = NULL;
			ccode = -ENOMEM;
			goto err_exit;
		}

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
	} else {
		/**
		 * new sock is accepted and a new
		 * connection is created, allocated elements are initialized
		 * p is a pointer to a connected socket
		 **/
		/** now we need to read and write messages **/
		c->connected = (struct socket *)p;
		c->worker = kthread_create_worker(0, "server thread");
		if (c->worker == ERR_PTR(-ENOMEM)) {
			c->worker = NULL;
			ccode = -ENOMEM;
			goto err_exit;
		}
		link_new_connection_work(c, &connections);
		kthread_init_work(&c->work, k_msg_server);
		is_queued = kthread_queue_work(c->worker, &c->work);
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

/******************************************************************************/
/**
 * @brief: break the listening kernel thread out of its polling loop
 *
 * @param[in] void
 * @returns void
 *
 * @note: This is a hack, should be replaced by a signal.
 *
 ******************************************************************************/

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
	if (! down_interruptible(&listener->s_lock))
	{
		up(&listener->s_lock);
	}

	return;
}


/******************************************************************************/
/**
 * @brief: release a lock held in an open file
 *
 * @param[in] f - pointer to an open struct file
 * @param[in] l - pointer to a struct file_lock
 * @returns OK (0) upon success, non-zero otherwise
 *
 * @note:
 *
 ******************************************************************************/

static int unlock_file(struct file *f, struct file_lock *l)
{
	if (!f || !l) {
		return -EINVAL;
	}

	return vfs_cancel_lock(f, l);
}

/******************************************************************************/
/**
 * @brief: obtain an exclusive lock a lock on an open file
 *
 * @param[in] f - pointer to an open struct file
 * @param[in] l - pointer to a struct file_lock
 * @returns OK (0) upon success, non-zero otherwise
 *
 * @note:
 *
 ******************************************************************************/
static int lock_file(struct file *f, struct file_lock *l)
{
	if (!f || !l) {
		return -EINVAL;
	}

	l->fl_flags = FL_FLOCK;
	l->fl_type  = F_WRLCK;

	/**
	 * POSIX protocol says this lock will be released if the module
	 * crashes or exits
	 **/
	return vfs_lock_file(f, F_SETLK, l, NULL);
}

/******************************************************************************/
/**
 * @brief: close the lock file used to protect the domain socket
 *
 * @param[in] f - pointer to an open struct file
 * @returns OK (0) upon success, non-zero otherwise
 *
 * @note: before unlinking the socket file, the module must gain an
 *        exclusive lock on the lock file. a cooperative process holding
 *        the lock will prevent unlinking the file prematurely.
 *
 ******************************************************************************/

static int close_lock_file(struct file *f)
{
	if (!f) {
		return -EINVAL;
	}
	if (!file_count(f)) {
		return 0;
	}

	return filp_close(f, NULL);
}

/******************************************************************************/
/**
 * @brief: open the lock file, creating it if necessary
 *
 * @param[in] lock_name - string containing the name of the lock file
 * @returns a pointer to the opened struct file if successful, an error
 *          cast as a pointer upon failure.
 *
 * @note: The lock file can prevent another cooperative process from unlinking
 *        the domain socket file prematurely
 *
 ******************************************************************************/

static struct file *open_lock_file(char *lock_name)
{
	struct file *lock_file = NULL;
	if (! lock_name) {
		return ERR_PTR(-EINVAL);
	}
	/**
	 * open the lock file, create it if necessary
	 **/
	lock_file = filp_open(lock_name, O_RDONLY | O_CREAT, S_IRUSR | S_IWUSR);
	if (IS_ERR(lock_file) || ! lock_file) {
		printk(KERN_DEBUG "error opening or creating the socket lock\n");
		return ERR_PTR(-ENFILE);
	}
	return lock_file;
}


/******************************************************************************/
/**
 * @brief: remove the file representing the listening domain socket
 *
 * @param[in] pointer to the name of the socket file
 * @param[in] pointer to the name of the lock file
 * @returns OK (0) or non-negative error number
 *
 * @note: The lock file protects
 *
 ******************************************************************************/

static int unlink_sock_name(char *sock_name, char *lock_name)
{
	struct path name_path = {.mnt = 0};
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
		if (f_lock_file == NULL) {
			f_lock_file = open_lock_file(lock_name);
		}
		need_lock = lock_file(f_lock_file, &f_lock);
	}

	if (!need_lock && !ccode) {
		ccode = vfs_unlink(name_path.dentry->d_parent->d_inode,
				   name_path.dentry,
				   NULL);
	}
	return ccode;
}

/******************************************************************************/
/**
 * @brief: delete a file from the vfs
 *
 * @param[in] filename - pointer to a string with the file name
 * @returns OK (0) upon success, non-zero otherwise.
 *
 * @note:
 *
 ******************************************************************************/

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

/******************************************************************************/
/**
 * @brief: retrieve file attributes
 *
 * @param[in]      f - pointer to an open struct file
 * @param[in, out] k - pointer to a struct kstat
 * @returns OK (0) upon success, non-zero otherwise
 *
 * @note:
 *
 ******************************************************************************/

int file_getattr(struct file *f, struct kstat *k)
{
	int ccode = 0;
	memset(k, 0x00, sizeof(struct kstat));
	ccode = vfs_getattr(&f->f_path, k, 0x00000fffU, KSTAT_QUERY_FLAGS);
	return ccode;
}

/******************************************************************************/
/**
 * @brief: open, write to, and close a file
 *
 * @param[in]      name - pointer to string containing the name of the file
 * @param[in, out] buf -  pointer to a buffer which will contain bytes read
 * @param[in]      count - the size of the buffer and the number of bytes to read
 * @param[out]     pos - pointer to a long integer which indicates the offset
 *                 from which to read, and provides the ending offset.
 * @returns        the number of bytes read, or a negative error number
 *
 *
 ******************************************************************************/

size_t write_file(char *name, void *buf, size_t count, loff_t * pos)
{
	ssize_t ccode;
	struct file *f;
	f = filp_open(name, O_RDWR, 0);
	if (f) {
		ccode = __kernel_write(f, buf, count, pos);
		if (ccode < 0) {
			pr_err("Unable to write file: %s (%ld)", name, ccode);
		}
		filp_close(f, 0);
	} else {
		ccode = -EBADF;
		pr_err("Unable to open file: %s (%ld)", name, ccode);
	}
	return ccode;
}

/******************************************************************************/
/**
 * @brief: allocate a buffer, open a file, read from the file into the buffer
 *
 * @param[in]      name - string containing the name of the file
 * @param[in, out] buf - double pointer that will contain the allocated buffer
 * @param[in]      max_count - maximum bytes to read from the file
 * @param[in, out] pos - pointer to the offset in the file from which to read,
 *                 updated to indicate the offset for the next read
 * @returns         number of bytes read
 *
 * @note: this function is overkill for reading the target file, but we may need
 *        to read longer files, such as the states file
 *
 ******************************************************************************/

size_t read_file(char *name, void **buf, size_t max_count, loff_t *pos)
{
	ssize_t ccode = 0;
	struct file *f = NULL;

	assert(buf);
	*buf = NULL;
	assert(pos);
	*pos = 0LL;

	f = filp_open(name, O_RDONLY, 0);
	if (f) {
		ssize_t chunk = 0x40, allocated = 0, cursor = 0;
		*buf = kzalloc(chunk, GFP_KERNEL);
		if (*buf) {
			allocated = chunk;
		} else {
			ccode =  -ENOMEM;
			goto out_err;
		}

		do {
			/**
			 * read one chunk at a time
			 **/
			cursor = *pos; /* initially zero, then positioned with further reads */
			ccode = kernel_read(f, *buf + cursor, chunk, pos);
			if (ccode < 0) {
				pr_err("Unable to read file chunk: %s (%ld)", name, ccode);
				goto out_err;
			}
			if (ccode > 0) {
				*buf = krealloc(*buf, allocated + chunk, GFP_KERNEL);
				if (! *buf) {
					ccode = -ENOMEM;
					goto out_err;
				}
				allocated += chunk;
			}
		} while (ccode && allocated <= max_count);
		filp_close(f, 0);
	} else {
		ccode = -EBADF;
		pr_err("Unable to open file: %s (%ld)", name, ccode);
	}
	return ccode;

out_err:
	if (f) {
		filp_close(f, 0);
	}
	if  (*buf) {
		kfree(*buf);
		*buf = NULL;
	}
	return ccode;
}


/******************************************************************************/
/**
 * @brief: read the hotplug state file for a single cpu
 *
 * @param[in] cpu - number of the cpu for which to read state
 * @returns   hotplug state for the cpu, or error -ENOMEM, -EBADF, -ERANGE
 *
 * @note:
 *
 ******************************************************************************/

static int32_t read_cpu_state_file(int cpu)
{
	int state = 0;
	int ccode = 0;
	char fname[48] = {0};
	void *result = NULL;
	loff_t pos = 0;

	ccode = snprintf(fname,
			 48,
			 "/sys/devices/system/cpu/cpu%d/hotplug/state",
			 cpu);
	if (ccode > 0) {
		ccode = read_file(fname,
				  &result,
				  16,
				  &pos);
		if (ccode > 0 && result != NULL) {
			ccode = kstrtoint((const char *)result, 10, &state);
			if (ccode >= 0) {
				ccode = (int32_t)state;
			}
		}
	}
	if (result != NULL) {
		kzfree(result);
	}
	return ccode;
}


/******************************************************************************/
/**
 * @brief: initiate a state change for a specific cpu by writing to it's target
 *         state file
 *
 * @param[in] cpu - the number of the target cpu
 * @param[in] target - the desired state of the cpu
 * @returns bytes written upon success, < 0 upon error.
 *
 * @note:
 *
 ******************************************************************************/

static int write_cpu_target_file(int cpu, int target)
{
	int ccode = 0;
	char fname[48] = {0};
	char buf[16] = {0};
	loff_t pos = 0;
	if (target < 0 || target > 0x1ff) {
		return -ERANGE;
	}

	ccode = snprintf(fname,
			 48,
			 "/sys/devices/system/cpu/cpu%d/hotplug/target",
			 cpu);
	if (ccode > 0) {
		ccode = snprintf(buf, 16, "%d\n", target);
		if (ccode > 0) {
		  ccode = write_file(fname, buf, 16, &pos);
		}
	}
	return ccode;
}

/******************************************************************************/
/**
 * @brief: Copy a single cpu bitmask.
 *
 * @param[out] dst - pointer to the destination bitmask
 * @param[in]  src - pointer to the source bitmask
 * @returns OK (0) or -ERANGE, which means the copy has been truncated
 *
 * @note: The copy truncation might occur because we assume a hard limit on CPUs
 *        of 512, while most kernels are configured with a limit of 8K, which
 *        consumes a lot of mostly unused storage.
 *
 ******************************************************************************/

static int copy_cpu_bitmask(struct cpumask *dst, struct cpumask *src)
{

	if (!dst || !src) {
		return -EINVAL;
	}
	if (nr_cpu_ids <= MAX_NR_CPUS) {
		cpumask_copy(dst, src);
		return OK;
	}
	bitmap_copy(cpumask_bits(dst), cpumask_bits(src), MAX_NR_CPUS);
	return -ERANGE;
}


/******************************************************************************/
/**
 * @brief: hook cpu hotplug state transitions
 *
 * @returns dynamic state number assigned to this module
 *
 * @note: called upon initialization
 *
 ******************************************************************************/

static int cpu_hotplug_init(void)
{
	int ccode = 0;
	ccode = cpuhp_setup_state_nocalls(CPUHP_AP_ONLINE_DYN,
					  "x86/demo:online",
					  my_cpu_online,
					  my_cpu_going_offline);

	return ccode;
}

/******************************************************************************/
/**
 * @brief: un-hook this module from cpu hotplug state transitions
 *
 * @returns void
 *
 * @note: called upon module unload
 *
 ******************************************************************************/

static void cpu_hotplug_cleanup(void)
{
	cpuhp_remove_state_nocalls(CPUHP_AP_ONLINE_DYN);
}


/******************************************************************************/
/**
 * @brief: module initialization
 *
 * @returns OK (0) upon success, -ENFILE or -ENOMEM upon failure
 *
 * @note:
 *
 ******************************************************************************/

int __init socket_interface_init(void)
{
	int ccode = import_symbols(sym_imports, SIZE_IMPORTS);
	if (ccode) {
		return ccode;
	}

	_cpu_report_state = (int (*)(int))find_private(sym_imports,
					 "cpu_report_state",
					 SIZE_IMPORTS);
	if (_cpu_report_state == NULL) {
		return -ENFILE;
	}

	INIT_LIST_HEAD(&connections);
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

	init_connection(listener, SOCK_LISTEN, socket_name);
	return 0;
}



/******************************************************************************/
/**
 * @brief: clean-up module upon unloading
 *
 * @note:
 *
 ******************************************************************************/

void __exit socket_interface_exit(void)
{
	struct connection *c = NULL;
	atomic64_set(&SHOULD_SHUTDOWN, 1);
	cpu_hotplug_cleanup();
	awaken_accept_thread();

	/**
	 * go through list of connections, destroy each connection
	 **/
	unlock_file(f_lock_file, &f_lock);
	close_lock_file(f_lock_file);
	unlink_sock_name(socket_name, lockfile_name);
	spin_lock(&connections_lock);

	c = list_first_entry_or_null(&connections, struct connection, l);
	while (c != NULL) {
		list_del(&c->l);
		spin_unlock(&connections_lock);
		destroy_connection(c);
		kzfree(c);
		spin_lock(&connections_lock);
		c = list_first_entry_or_null(&connections, struct connection, l);
	}
	spin_unlock(&connections_lock);
	unlink_file(lockfile_name);
	return;
}

module_init(socket_interface_init);
module_exit(socket_interface_exit);


MODULE_LICENSE(_MODULE_LICENSE);
MODULE_AUTHOR(_MODULE_AUTHOR);
MODULE_DESCRIPTION(_MODULE_INFO);
