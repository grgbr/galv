/*
 * FIXME: move me to utils/etux !!!!!
 */

#ifndef _GALV_ETUX_H
#define _GALV_ETUX_H

#include <galv/cdefs.h>
#include <utils/fd.h>
#include <sys/socket.h>

#define etux_sock_assert_api(_expr) \
	stroll_assert("etux:sock", _expr)

/**
 * Send a buffer over socket to its connected peer if any.
 *
 * @return A non zero number of bytes sent upon success, a negative `errno`
 *         like code otherwise.
 * @retval -EAGAIN     Underlying socket outgoing buffer full, try again later
 * @retval -EALREADY   Another (TCP) fast open is already in progress
 * @retval -EMSGSIZE   Message could not be sent atomically (MTU ?)
 * @retval -EPIPE      Remote peer consumed all of its data and closed
 * @retval -ECONNRESET Remote peer closed while there were still unhandled data
 *                     in its socket buffer
 * @retval -ENOBUFS    Underlying network interface output queue full, i.e,
 *                     transient congestion or interface stopped
 *                     (administratively ?)
 * @retval -EINTR      Interrupted by a signal before any data was transmitted
 * @retval -ENOMEM     No more memory available
 *
 * When size is zero, buff may be NULL to send a zero sized payload for datagram
 * and seqpacket sockets.
 */
static inline __warn_result
ssize_t
etux_sock_send(int fd, const void * __restrict buff, size_t size, int flags)
{
#define ETUX_SOCK_VALID_SEND_FLAGS \
	(MSG_CONFIRM | MSG_DONTROUTE | MSG_DONTWAIT | MSG_EOR | \
	 MSG_MORE | MSG_NOSIGNAL | MSG_OOB)

	etux_sock_assert_api(fd >= 0);
	etux_sock_assert_api(!buff || size);
	etux_sock_assert_api(!size || (size <= SSIZE_MAX));
	etux_sock_assert_api(!(flags & ~ETUX_SOCK_VALID_SEND_FLAGS));

	ssize_t bytes;

	bytes = send(fd, buff, size, flags);
	if (bytes >= 0)
		return bytes;

	/*
	 * Should never happen since we should have been validated by a previous
	 * connect(2) call.
	 */
	etux_sock_assert_api(errno != EACCES);

	etux_sock_assert_api(errno != EBADF);
	etux_sock_assert_api(errno != EDESTADDRREQ);
	etux_sock_assert_api(errno != EFAULT);
	etux_sock_assert_api(errno != EINVAL);
	etux_sock_assert_api(errno != EISCONN);
	etux_sock_assert_api(errno != ENOTCONN);
	etux_sock_assert_api(errno != ENOTSOCK);
	etux_sock_assert_api(errno != EOPNOTSUPP);

	return -errno;
}

/**
 * Receive from a socket connected peer if any.
 *
 * @return Number of bytes received upon success, a negative `errno` like code
 *         otherwise.
 * @retval -EAGAIN       Underlying socket incoming buffer empty, try again
 *                       later
 * @retval -ECONNREFUSED Remote peer refused to allow the network connection
 *                       (typically because it is not running the requested
 *                       service)
 * @retval -EINTR        Interrupted by a signal before any data was received
 * @retval -ENOMEM       No more memory available
 */
static inline __utils_nonull(2) __warn_result
ssize_t
etux_sock_recv(int fd, void * __restrict buff, size_t size, int flags)
{
#define ETUX_SOCK_VALID_RECV_FLAGS \
	(MSG_DONTWAIT | MSG_ERRQUEUE | MSG_OOB | MSG_PEEK | MSG_TRUNC | \
	 MSG_WAITALL)
	etux_sock_assert_api(fd >= 0);
	etux_sock_assert_api(buff);
	etux_sock_assert_api(size);
	etux_sock_assert_api(size <= SSIZE_MAX);
	etux_sock_assert_api(!(flags & ~ETUX_SOCK_VALID_RECV_FLAGS));

	ssize_t bytes;

	bytes = recv(fd, buff, size, flags);
	if (bytes >= 0)
		return bytes;

	etux_sock_assert_api(errno != EBADF);
	etux_sock_assert_api(errno != EFAULT);
	etux_sock_assert_api(errno != EINVAL);
	etux_sock_assert_api(errno != ENOTCONN);
	etux_sock_assert_api(errno != ENOTSOCK);

	return -errno;
}

static inline __utils_nonull(2) __warn_result
int
etux_sock_connect(int                                fd,
                  const struct sockaddr * __restrict peer_addr,
                  socklen_t                          addr_size)
{
	etux_sock_assert_api(fd >= 0);
	etux_sock_assert_api(peer_addr);
	etux_sock_assert_api(addr_size >= sizeof(*peer_addr));

	if (!connect(fd, peer_addr, addr_size))
		return 0;

	etux_sock_assert_api(errno != EAFNOSUPPORT);
	etux_sock_assert_api(errno != EBADF);
	etux_sock_assert_api(errno != EFAULT);
	etux_sock_assert_api(errno != EISCONN);
	etux_sock_assert_api(errno != ENOTSOCK);

	return -errno;
}

/**
 * Accept a socket connection.
 *
 * @return New accepted socket file descriptor if successful, a negative `errno`
 *         like code otherwise.
 * @retval -EAGAIN       No queued connection to be accepted, try again later
 * @retval -ECONNABORTED A queued connection has been aborted
 * @retval -EINTR        Interrupted by a signal before any connection could be
 *                       accepted
 * @retval -EMFILE       Maximum per-process number of opened file descriptors
 *                       reached
 * @retval -ENFILE       Maximum system number of opened file descriptors
 *                       reached
 * @retval -ENOBUFS      Not enought socket buffer memory or same as -ENOMEM
 * @retval -ENOMEM       No more (system / process) memory available
 * @retval -EPROTO       Protocol error
 * @retval -EPERM        Connection rejected by firewall rules
 *
 * @note
 * As stated into @man{accept4(2)}, additional protocol specific network errors
 * may be returned. Various Linux kernels can return other errors such as
 * `ENOSR`, `ESOCKTNOSUPPORT`, `EPROTONOSUPPORT`, `ETIMEDOUT` and `ERESTARTSYS`.
 */
static inline __warn_result
int
etux_sock_accept(int                          fd,
                 struct sockaddr * __restrict peer_addr,
                 socklen_t * __restrict       peer_size,
                 int                          flags)
{
	etux_sock_assert_api(fd >= 0);
	etux_sock_assert_api(!peer_addr || peer_size);
	etux_sock_assert_api(!peer_size || (*peer_size >= sizeof(sa_family_t)));
	etux_sock_assert_api(!(flags & ~(SOCK_NONBLOCK | SOCK_CLOEXEC)));

	int sk;

	sk = accept4(fd, peer_addr, peer_size, flags);
	if (sk >= 0)
		return sk;

	etux_sock_assert_api(errno != EBADF);
	etux_sock_assert_api(errno != EFAULT);
	etux_sock_assert_api(errno != EINVAL);
	etux_sock_assert_api(errno != ENOTSOCK);
	etux_sock_assert_api(errno != EOPNOTSUPP);

	return -errno;
}

static inline __utils_nothrow __warn_result
int
etux_sock_listen(int fd, int backlog)
{
	etux_sock_assert_api(fd >= 0);
	etux_sock_assert_api(backlog >= 0);

	if (!listen(fd, backlog))
		return 0;

	etux_sock_assert_api(errno != EBADF);
	etux_sock_assert_api(errno != ENOTSOCK);
	etux_sock_assert_api(errno != EOPNOTSUPP);

	return -errno;
}

/**
 * Shutdow part(s) of a full-duplex socket.
 */
static inline __utils_nothrow
void
etux_sock_shutdown(int fd, int how)
{
	etux_sock_assert_api(fd >= 0);
	etux_sock_assert_api((how == SHUT_RD) ||
	                     (how == SHUT_WR) ||
	                     (how == SHUT_RDWR));

	int err __unused;

	err = shutdown(fd, how);
	etux_sock_assert_api(!err);
}

/**
 * Close a socket.
 *
 * @return 0 if succesful, a negative `errno` like code otherwise.
 * @retval -EINTR A signal raised during closure
 * @retval -EIO   An I/O error occured
 *
 * On Linux, in case of error, *DO NOT* ever retry to close the same file
 * descriptor again. This is useless and the error code is returned for
 * informational purpose only.
 *
 * See section *Dealing with error returns from close()* of @man{close(2)} for
 * further details.
 */
static inline
int
etux_sock_close(int fd)
{
	int ret;

	ret = ufd_close(fd);

	etux_sock_assert_api(ret != -ENOSPC);
	etux_sock_assert_api(ret != -EDQUOT);

	return ret;
}

#endif /* _GALV_ETUX_H */
