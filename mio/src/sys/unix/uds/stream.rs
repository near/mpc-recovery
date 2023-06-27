use log::debug;

use super::{socket_addr, SocketAddr};
use crate::sys::unix::net::new_socket;

use std::io;
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::os::unix::net;
use std::path::Path;

pub(crate) fn connect(path: &Path) -> io::Result<net::UnixStream> {
    debug!("mio uds connect start");
    let (sockaddr, socklen) = socket_addr(path)?;
    debug!("mio uds connect addr 1: {:?} {}", sockaddr, socklen);
    let sockaddr = &sockaddr as *const libc::sockaddr_un as *const libc::sockaddr;
    debug!("mio uds connect addr 2: {:?}", sockaddr);

    let fd = new_socket(libc::AF_UNIX, libc::SOCK_STREAM)?;
    debug!("mio uds connect fd: {:?}", fd);
    let socket = unsafe { net::UnixStream::from_raw_fd(fd) };
    debug!("mio uds connect socket: {:?}", socket);
    match syscall!(connect(fd, sockaddr, socklen)) {
        Ok(_) => {
            debug!("mio uds connect ok");
        }
        Err(ref err) if err.raw_os_error() == Some(libc::EINPROGRESS) => {
            debug!("mio uds connect error 1: {:?}", err);
        }
        Err(e) => {
            debug!("mio uds connect error 2: {:?}", e);
            return Err(e);
        }
    }

    Ok(socket)
}

pub(crate) fn pair() -> io::Result<(net::UnixStream, net::UnixStream)> {
    super::pair(libc::SOCK_STREAM)
}

pub(crate) fn local_addr(socket: &net::UnixStream) -> io::Result<SocketAddr> {
    super::local_addr(socket.as_raw_fd())
}

pub(crate) fn peer_addr(socket: &net::UnixStream) -> io::Result<SocketAddr> {
    super::peer_addr(socket.as_raw_fd())
}
