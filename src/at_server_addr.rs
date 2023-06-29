use std::net::{SocketAddr, ToSocketAddrs};

#[derive(Debug)]
pub struct AtServerAddr {
    pub host: String,
    pub port: u16,
}

impl AtServerAddr {
    pub fn new(host: String, port: u16) -> Self {
        AtServerAddr { host, port }
    }
}

impl ToSocketAddrs for AtServerAddr {
    type Iter = std::vec::IntoIter<SocketAddr>;

    fn to_socket_addrs(&self) -> std::io::Result<Self::Iter> {
        let addr = format!("{}:{}", self.host, self.port);
        Ok(addr.to_socket_addrs()?.collect::<Vec<_>>().into_iter())
    }
}
