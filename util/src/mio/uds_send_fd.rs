use std::os::fd::{AsFd, AsRawFd};
use std::{
    borrow::{Borrow, BorrowMut},
    cmp::min,
    collections::VecDeque,
    io::Write,
    marker::PhantomData,
};
use uds::UnixStreamExt as FdPassingExt;

use crate::{repeat, return_if};

/// A structure that facilitates writing data and file descriptors to a Unix domain socket
///
/// # Example
///
/// ```rust
/// use std::io::{Read, Write};
/// use std::net::UdpSocket;
/// use std::os::fd::{AsFd, AsRawFd};
///
/// use mio::net::UnixStream;
/// use rosenpass_util::mio::WriteWithFileDescriptors;
///
/// // Create socket descriptors that should be sent (not limited to UDP sockets)
/// let peer_endpoint = "[::1]:0";
/// let peer_socket = UdpSocket::bind(peer_endpoint).expect("bind failed");
/// let peer_socket_fd = peer_socket.as_fd();
/// let mut fds_to_send = vec![&peer_socket_fd].into();
///
/// // Create writable end (must be an Unix Domain Socket)
/// // In this case, the readable end of the connection can be ignored
/// let (mut dummy_sink, io_stream) = UnixStream::pair().expect("failed to create socket pair");
/// let mut writable_stream = WriteWithFileDescriptors::<UnixStream, _, _, _>::new(
/// &io_stream, &mut fds_to_send);
///
/// // Send data and file descriptors (note that at least one byte should be written)
/// writable_stream.write(&[0xffu8; 42]).expect("failed to write");
/// // Discard data; the dummy_sink is only required to keep the connection alive here
/// let mut recv_buffer = Vec::<u8>::new();
/// dummy_sink.read(&mut recv_buffer[..]).expect("error reading from socket");
/// writable_stream.flush().expect("failed to flush"); // Currently a NOOP
///
/// // The wrapped components can still be accessed
/// let (socket, fds) = writable_stream.into_parts();
/// assert_eq!(socket.as_raw_fd(), io_stream.as_raw_fd());
/// assert!(fds_to_send.is_empty(), "Failed to send file descriptors");
///
/// // Shutdown, cleanup, etc. goes here ...
/// ```
pub struct WriteWithFileDescriptors<Sock, Fd, BorrowSock, BorrowFds>
where
    Sock: FdPassingExt,
    Fd: AsFd,
    BorrowSock: Borrow<Sock>,
    BorrowFds: BorrowMut<VecDeque<Fd>>,
{
    socket: BorrowSock,
    fds: BorrowFds,
    _sock_dummy: PhantomData<Sock>,
    _fd_dummy: PhantomData<Fd>,
}

impl<Sock, Fd, BorrowSock, BorrowFds> WriteWithFileDescriptors<Sock, Fd, BorrowSock, BorrowFds>
where
    Sock: FdPassingExt,
    Fd: AsFd,
    BorrowSock: Borrow<Sock>,
    BorrowFds: BorrowMut<VecDeque<Fd>>,
{
    /// Creates a new `WriteWithFileDescriptors` instance with the given socket and file descriptor queue
    pub fn new(socket: BorrowSock, fds: BorrowFds) -> Self {
        let _sock_dummy = PhantomData;
        let _fd_dummy = PhantomData;
        Self {
            socket,
            fds,
            _sock_dummy,
            _fd_dummy,
        }
    }

    /// Consumes this instance and returns the underlying socket and file descriptor queue
    pub fn into_parts(self) -> (BorrowSock, BorrowFds) {
        let Self { socket, fds, .. } = self;
        (socket, fds)
    }

    /// Returns a reference to the underlying socket
    pub fn socket(&self) -> &Sock {
        self.socket.borrow()
    }

    /// Returns a reference to the file descriptor queue
    pub fn fds(&self) -> &VecDeque<Fd> {
        self.fds.borrow()
    }

    /// Returns a mutable reference to the file descriptor queue
    pub fn fds_mut(&mut self) -> &mut VecDeque<Fd> {
        self.fds.borrow_mut()
    }
}

impl<Sock, Fd, BorrowSock, BorrowFds> WriteWithFileDescriptors<Sock, Fd, BorrowSock, BorrowFds>
where
    Sock: FdPassingExt,
    Fd: AsFd,
    BorrowSock: BorrowMut<Sock>,
    BorrowFds: BorrowMut<VecDeque<Fd>>,
{
    /// Returns a mutable reference to the underlying socket
    pub fn socket_mut(&mut self) -> &mut Sock {
        self.socket.borrow_mut()
    }
}

impl<Sock, Fd, BorrowSock, BorrowFds> Write
    for WriteWithFileDescriptors<Sock, Fd, BorrowSock, BorrowFds>
where
    Sock: FdPassingExt,
    Fd: AsFd,
    BorrowSock: Borrow<Sock>,
    BorrowFds: BorrowMut<VecDeque<Fd>>,
{
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        // At least one byte of real data should be sent when sending ancillary data. -- unix(7)
        return_if!(buf.is_empty(), Ok(0));

        // The kernel constant SCM_MAX_FD defines a limit on the number of file descriptors
        // in the array.  Attempting to  send  an  array  larger  than  this  limit  causes
        // sendmsg(2)  to fail with the error EINVAL.  SCM_MAX_FD has the value 253 (or 255
        // before Linux 2.6.38).
        // -- unix(7)
        const SCM_MAX_FD: usize = 253;
        let buf = match self.fds().len() <= SCM_MAX_FD {
            false => &buf[..1], // Force caller to immediately call write() again to send its data
            true => buf,
        };

        // Allocate the buffer for the file descriptor array
        let fd_no = min(SCM_MAX_FD, self.fds().len());
        let mut fd_buf = [0; SCM_MAX_FD]; // My kingdom for alloca(3)
        let fd_buf = &mut fd_buf[..fd_no];

        // Fill the file descriptor array
        for (raw, fancy) in fd_buf.iter_mut().zip(self.fds().iter()) {
            *raw = fancy.as_fd().as_raw_fd();
        }

        // Send data and file descriptors
        let bytes_written = self.socket().send_fds(buf, fd_buf)?;

        // Drop the file descriptors from the Deque
        repeat!(fd_no, {
            self.fds_mut().pop_front();
        });

        Ok(bytes_written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
