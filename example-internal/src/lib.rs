extern crate libc;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate libnss;
extern crate trust_dns_resolver;

use libnss::host::{AddressFamily, Addresses, Host, HostHooks};
use libnss::interop::Response;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::net::SocketAddr;
use trust_dns_resolver::Resolver;
use trust_dns_resolver::config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts};

struct InternalHost;
libnss_host_hooks!(internal, InternalHost);

impl HostHooks for InternalHost {
    fn get_all_entries() -> Response<Vec<Host>> {
        Response::Success(vec![Host {
            name: "test.internal".to_string(),
            addresses: Addresses::V6(vec![Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 2)]),
            aliases: vec!["other.internal".to_string()],
        }])
    }

    fn get_host_by_addr(addr: IpAddr) -> Response<Host> {
        match addr {
            IpAddr::V4(addr) => {
                if addr.octets() == [127, 0, 0, 1] {
                    Response::Success(Host {
                        name: "test.internal".to_string(),
                        addresses: Addresses::V4(vec![Ipv4Addr::new(127, 0, 0, 1)]),
                        aliases: vec![],
                    })
                } else {
                    Response::NotFound
                }
            }
            _ => Response::NotFound,
        }
    }

    fn get_host_by_name(name: &str, _family: AddressFamily) -> Response<Host> {
        if name.ends_with(".internal") {
            let nameserver = NameServerConfig {
                socket_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 243, 43, 53)), 53),
                protocol: Protocol::Udp,
                tls_dns_name: None,
            };
            // let nameservergroup = NameServerConfigGroup::from(vec![nameserver]);
            let mut resolv_config = ResolverConfig::new();
            resolv_config.add_name_server(nameserver);

            // Construct a new Resolver with default configuration options
            let resolver = match Resolver::new(resolv_config, ResolverOpts::default()) {
                Ok(r) => r,
                Err(_) => {
                    return Response::Unavail
                }
            };

            // Lookup the IP addresses associated with a name.
            // The final dot forces this to be an FQDN, otherwise the search rules as specified
            //  in `ResolverOpts` will take effect. FQDN's are generally cheaper queries.
            match resolver.lookup_ip(&name) {
                Ok(response) => {
                    // lookup dns ok
                    if let Some(address) = response.iter().next() {
                        match address {
                            IpAddr::V4(addr) => {
                                Response::Success(Host {
                                    name: name.to_string(),
                                    addresses: Addresses::V4(vec![addr]),
                                    aliases: vec![],
                                })
                            },
                            // ipv6 not supported
                            IpAddr::V6(_addr) => {
                                Response::NotFound
                            },
                        }
                    } else {
                        // lookup not found
                        Response::NotFound
                    }
                },
                Err(_) => {
                    // lookup error
                    Response::NotFound
                },
            }
        } else {
            // others
            Response::NotFound
        }
    }
}
