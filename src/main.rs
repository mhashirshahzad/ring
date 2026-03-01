use libc::*;
use std::io;
use std::net::{Ipv4Addr, ToSocketAddrs};
use std::time::{Duration, Instant};
use std::{env, mem, process, thread};
use url::Url;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let host_str = get_cli_arg();

    let ip: Ipv4Addr = match resolve_host(&host_str) {
        Ok(ip) => ip,
        Err(e) => {
            print_error(format!("{}: {}", host_str, e));
            process::exit(1);
        }
    };

    println!(
        "\x1b[32mPING\x1b[0m {} (\x1b[33m{}\x1b[0m) 64 bytes of data.",
        host_str, ip
    );

    icmp_loop(ip)
}

/// Get the CLI argument or exit with usage
fn get_cli_arg() -> String {
    env::args().nth(1).unwrap_or_else(|| {
        print_error(format!("Usage: ring \x1b[33m<host>\x1b[0m"));
        process::exit(1);
    })
}

/// Resolve hostname to IPv4 address
fn resolve_host(host: &str) -> Result<Ipv4Addr, Box<dyn std::error::Error>> {
    let addr_iter = (host, 0).to_socket_addrs()?; // port 0 for resolution only
    for addr in addr_iter {
        if let std::net::SocketAddr::V4(v4) = addr {
            return Ok(*v4.ip());
        }
    }
    Err(format!("No IPv4 address found for {}", host).into())
}

/// ICMP ping loop
fn icmp_loop(ip: Ipv4Addr) -> Result<(), Box<dyn std::error::Error>> {
    unsafe {
        let sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
        if sock < 0 {
            print_error("Failed to create ICMP socket".into());
            return Err(Box::new(io::Error::last_os_error()));
        }

        let mut addr_struct: libc::sockaddr_in = mem::zeroed();
        addr_struct.sin_family = libc::AF_INET as u16;
        addr_struct.sin_addr.s_addr = u32::from(ip).to_be();

        let mut seq: u16 = 1;
        let identifier: u16 = 0x1234;

        loop {
            let mut packet = [0u8; 64];
            packet[0] = 8; // ICMP_ECHO_REQUEST
            packet[1] = 0;
            packet[4..6].copy_from_slice(&identifier.to_be_bytes());
            packet[6..8].copy_from_slice(&seq.to_be_bytes());

            let csum = checksum(&packet);
            packet[2..4].copy_from_slice(&csum.to_be_bytes());

            let start = Instant::now();
            let sent = libc::sendto(
                sock,
                packet.as_ptr() as *const _,
                packet.len(),
                0,
                &addr_struct as *const _ as *const libc::sockaddr,
                mem::size_of::<libc::sockaddr_in>() as u32,
            );

            if sent < 0 {
                print_error("Send failed".into());
                break;
            }

            let mut recv_buf = [0u8; 1024];
            let received = libc::recv(sock, recv_buf.as_mut_ptr() as *mut _, recv_buf.len(), 0);

            if received > 0 && recv_buf[0] == 0 {
                // ICMP_ECHO_REPLY
                let rtt = start.elapsed();
                print_success(format!(
                    "64 bytes from \x1b[33m{}\x1b[0m: icmp_seq=\x1b[34m{}\x1b[0m time=\x1b[35m{:.1} ms\x1b[0m",
                    ip,
                    seq,
                    rtt.as_secs_f64() * 1000.0
                ));
            }

            seq = seq.wrapping_add(1);
            thread::sleep(Duration::from_secs(1));
        }

        libc::close(sock);
    }
    Ok(())
}

/// Prints `[Success]` along with the passed in message in green
fn print_success(msg: String) {
    println!("\x1b[32m[Success]\x1b[0m {}", msg);
}

/// Prints `[Error!]` along with the passed in message in red
fn print_error(msg: String) {
    eprintln!("\x1b[31m[Error!]\x1b[0m {}", msg);
}

/// Calculates ICMP checksum
fn checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut chunks = data.chunks_exact(2);

    for chunk in &mut chunks {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }

    if let Some(&rem) = chunks.remainder().first() {
        sum += (rem as u32) << 8;
    }

    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    !(sum as u16)
}
