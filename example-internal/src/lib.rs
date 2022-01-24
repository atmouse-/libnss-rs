extern crate libc;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate libnss;
extern crate trust_dns_resolver;
use std::fs::File;
use std::io::Read;
use std::str::Bytes;

use libnss::host::{AddressFamily, Addresses, Host, HostHooks};
use libnss::interop::Response;

use std::net::{IpAddr, Ipv4Addr};
use std::net::SocketAddr;
use trust_dns_resolver::Resolver;
use trust_dns_resolver::config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts};

struct InternalHost;
libnss_host_hooks!(internal, InternalHost);

fn config_getns() -> IpAddr {
    let msg_err = "/etc/libnss-internal.conf open failed";
    let mut fp = File::open("/etc/libnss-internal.conf").expect(msg_err);
    let mut buf = [0; 15];
    let _ = fp.read(&mut buf).expect(msg_err);
    let x: String = String::from_utf8_lossy(&buf).to_string();
    let x = x.trim_end_matches(char::from(0)).trim_end_matches(char::from('\n'));
    let ns: IpAddr = x.parse().expect(msg_err);
    ns
}

impl HostHooks for InternalHost {
    fn get_all_entries() -> Response<Vec<Host>> {
        Response::Success(vec![Host {
            name: "test.internal".to_string(),
            addresses: Addresses::V4(vec![Ipv4Addr::new(192, 168, 0, 199)]),
            aliases: vec!["other.internal".to_string()],
        }])
    }

    fn get_host_by_addr(_addr: IpAddr) -> Response<Host> {
        Response::NotFound
    }

    fn get_host_by_name(name: &str, _family: AddressFamily) -> Response<Host> {
        if name.ends_with(".internal") {
            let ns = config_getns();
            let nameserver = NameServerConfig {
                socket_addr: SocketAddr::new(ns, 53),
                protocol: Protocol::Udp,
                tls_dns_name: None,
                trust_nx_responses: true,
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
            match resolver.lookup_ip(name) {
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
