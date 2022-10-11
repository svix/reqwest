use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{self, Poll};

use hyper::client::connect::dns as hyper_dns;
use hyper::service::Service;
use once_cell::sync::Lazy;
use tokio::sync::Mutex;
use trust_dns_resolver::{
    config::{ResolverConfig, ResolverOpts},
    system_conf, AsyncResolver, TokioConnection, TokioConnectionProvider, TokioHandle,
};

use crate::error::BoxError;

type SharedResolver = Arc<AsyncResolver<TokioConnection, TokioConnectionProvider>>;

static SYSTEM_CONF: Lazy<io::Result<(ResolverConfig, ResolverOpts)>> =
    Lazy::new(|| system_conf::read_system_conf().map_err(io::Error::from));

#[derive(Clone)]
pub(crate) struct TrustDnsResolver {
    state: Arc<Mutex<State>>,
}

enum State {
    Init,
    Ready(SharedResolver),
}

impl TrustDnsResolver {
    pub(crate) fn new() -> io::Result<Self> {
        SYSTEM_CONF.as_ref().map_err(|e| {
            io::Error::new(e.kind(), format!("error reading DNS system conf: {}", e))
        })?;

        // At this stage, we might not have been called in the context of a
        // Tokio Runtime, so we must delay the actual construction of the
        // resolver.
        Ok(TrustDnsResolver {
            state: Arc::new(Mutex::new(State::Init)),
        })
    }
}

impl Service<hyper_dns::Name> for TrustDnsResolver {
    type Response = std::vec::IntoIter<SocketAddr>;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, name: hyper_dns::Name) -> Self::Future {
        let resolver = self.clone();
        Box::pin(async move {
            let mut lock = resolver.state.lock().await;

            let resolver = match &*lock {
                State::Init => {
                    let resolver = new_resolver().await?;
                    *lock = State::Ready(resolver.clone());
                    resolver
                }
                State::Ready(resolver) => resolver.clone(),
            };

            // Don't keep lock once the resolver is constructed, otherwise
            // only one lookup could be done at a time.
            drop(lock);

            let lookup = resolver.lookup_ip(name.as_str()).await?;

            let iter = lookup
                .into_iter()
                .filter_map(|ip| {
                    if is_allowed(ip) {
                        Some(SocketAddr::new(ip, 0))
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>()
                .into_iter();

            Ok(iter)
        })
    }
}

fn is_allowed(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(addr) => {
            !addr.is_private()
                   && !addr.is_loopback()
                && !addr.is_link_local()
                && !addr.is_broadcast()
                && !addr.is_documentation()
                && !is_shared(addr)
                && !is_reserved(addr)
                && !is_benchmarking(addr)
                && !starts_with_zero(addr)
        }
        IpAddr::V6(addr) => {
            !addr.is_multicast()
                && !addr.is_loopback()
                && !is_unicast_link_local(addr)
                && !is_unique_local(addr)
                && !addr.is_unspecified()
                && !is_documentation_v6(addr)
        }
    }
}

async fn new_resolver() -> Result<SharedResolver, BoxError> {
    let (config, opts) = SYSTEM_CONF
        .as_ref()
        .expect("can't construct TrustDnsResolver if SYSTEM_CONF is error")
        .clone();
    let resolver = AsyncResolver::new(config, opts, TokioHandle)?;
    Ok(Arc::new(resolver))
}

/// Util functions copied from the unstable standard library near identically
fn is_shared(addr: Ipv4Addr) -> bool {
    addr.octets()[0] == 100 && (addr.octets()[1] & 0b1100_0000 == 0b0100_0000)
}

fn is_reserved(addr: Ipv4Addr) -> bool {
    (addr.octets()[0] == 192 && addr.octets()[1] == 0 && addr.octets()[2] == 0)
        || (addr.octets()[0] & 240 == 240 && !addr.is_broadcast())
}

fn is_benchmarking(addr: Ipv4Addr) -> bool {
    addr.octets()[0] == 198 && (addr.octets()[1] & 0xfe) == 18
}

fn starts_with_zero(addr: Ipv4Addr) -> bool {
    addr.octets()[0] == 0
}

fn is_unicast_link_local(addr: Ipv6Addr) -> bool {
    (addr.segments()[0] & 0xffc0) == 0xfe80
}

fn is_unique_local(addr: Ipv6Addr) -> bool {
    (addr.segments()[0] & 0xfe00) == 0xfc00
}

fn is_documentation_v6(addr: Ipv6Addr) -> bool {
    (addr.segments()[0] == 0x2001) && (addr.segments()[1] == 0xdb8)
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use crate::dns::is_allowed;

    #[test]
    fn is_allowed_test() {
        assert!(!is_allowed(IpAddr::from([10, 254, 0, 0])));
        assert!(!is_allowed(IpAddr::from([192, 168, 10, 65])));
        assert!(!is_allowed(IpAddr::from([172, 16, 10, 65])));
        assert!(!is_allowed(IpAddr::from([0, 1, 2, 3])));
        assert!(!is_allowed(IpAddr::from([0, 0, 0, 0])));
        assert!(!is_allowed(IpAddr::from([127, 0, 0, 1])));
        assert!(!is_allowed(IpAddr::from([169, 254, 45, 1])));
        assert!(!is_allowed(IpAddr::from([255, 255, 255, 255])));
        assert!(!is_allowed(IpAddr::from([192, 0, 2 ,255])));
        assert!(!is_allowed(IpAddr::from([198, 51, 100, 65])));
        assert!(!is_allowed(IpAddr::from([203, 0, 113, 6])));
        assert!(!is_allowed(IpAddr::from([100, 100, 0, 0])));
        assert!(!is_allowed(IpAddr::from([192, 0, 0, 0])));
        assert!(!is_allowed(IpAddr::from([192, 0, 0, 255])));
        assert!(!is_allowed(IpAddr::from([250, 10, 20, 30])));
        assert!(!is_allowed(IpAddr::from([198, 18, 0, 0])));

        assert!(is_allowed(IpAddr::from([1, 1, 1, 1])));

        assert!(!is_allowed(IpAddr::from([0, 0, 0, 0, 0, 0, 0, 0x1])));

        assert!(is_allowed(IpAddr::from([0, 0, 0, 0xffff, 0, 0, 0, 0x1])));
    }
}
