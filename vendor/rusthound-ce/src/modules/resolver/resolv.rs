use log::{info,debug};
use colored::Colorize;

// Pathwarden patch: hickory-resolver 0.26 in place of trust-dns-resolver 0.23.
use hickory_resolver::config::*;
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::Resolver;

use std::net::{IpAddr,Ipv4Addr};
use std::collections::HashMap;
use std::time::Duration;
use crate::objects::computer::Computer;

/// Function to resolve all IP address from the LDAP FQDN vector
/// <https://docs.rs/hickory-resolver/latest/hickory_resolver/index.html>
/// <https://github.com/shadowsocks/shadowsocks-rust/blob/master/crates/shadowsocks-service/src/config.rs>
pub async fn resolving_all_fqdn(
   dns_tcp:       bool,
   name_server:   &String,
   fqdn_ip:       &mut HashMap<String, String>,
   vec_computer:  &[Computer]
) {
   info!("Resolving FQDN to IP address started...");
   for value in fqdn_ip.to_owned()
   {
      for i in 0..vec_computer.len()
      {
         if (*vec_computer[i].properties().name() == value.0.to_owned()) 
         && (*vec_computer[i].properties().enabled()) {
            debug!("Trying to resolve FQDN: {}",value.0.to_string());
            // Resolve FQDN to IP address
            let address = resolver(value.0.to_string(),dns_tcp,name_server).await;
            if let Some(addr) = address {
               fqdn_ip.insert(value.0.to_owned().to_string(),addr.to_owned().to_string());
               info!("IP address for {}: {}",&value.0.to_string().yellow().bold(),&addr.yellow().bold());
            }
         }
         continue
      }
   }
   info!("Resolving FQDN to IP address finished!");
}

/// Asynchronous function to resolve IP address from the ldap FQDN
pub async fn resolver(
   fqdn: String,
   dns_tcp: bool, 
   name_server: &String,
) -> Option<String>
{
   // Get configuration and options for resolver
   let (c,o) = make_resolver_conf(dns_tcp,name_server);

   // Construct a new Resolver with default configuration options
   let resolver = match Resolver::builder_with_config(c, TokioRuntimeProvider::default())
      .with_options(o)
      .build()
   {
      Ok(resolver) => resolver,
      Err(_err) => return None,
   };

   // Resolver
   let result = resolver.lookup_ip(fqdn);

   match result.await{
      Ok(response) => {
         let address = response.iter().next().expect("no addresses returned!");
         if address.is_ipv4() {
            return Some(address.to_string())
         }
      }
      Err(_err) => {},
   };
   None
}

/// Function to prepare resolver configuration
pub fn make_resolver_conf(
   dns_tcp: bool, 
   name_server: &String,
) -> (ResolverConfig,ResolverOpts) {
   let mut c = ResolverConfig::default();
   let mut ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
   // Port 53, as before (ConnectionConfig's default for UDP and TCP).
   let mut connection = ConnectionConfig::udp();
   if dns_tcp
   {
      connection = ConnectionConfig::tcp();
   }
   if !name_server.contains("127.0.0.1") {
      ip = name_server.parse::<IpAddr>().unwrap_or(std::net::IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
   }

   debug!("Protocol DNS: {}",if dns_tcp { "Tcp" } else { "Udp" });
   debug!("Name server DNS: {:?}",name_server.parse::<Ipv4Addr>());

   c.add_name_server(NameServerConfig::new(ip, false, vec![connection]));

   let mut o = ResolverOpts::default();
   o.timeout = Duration::new(0, 10);
   (c,o)
}