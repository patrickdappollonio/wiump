use anyhow::Result;
use clap::Parser;
use netstat2::*;
use std::io::Write;
use std::net::IpAddr;
use sysinfo::{Pid, ProcessesToUpdate, System};
use tabwriter::TabWriter;
use users::get_user_by_uid;

/// Simple process info structure.
struct ProcessInfo {
    pid: u32,
    name: String,
}

/// Our unified socket structure.
struct SocketInfo {
    processes: Vec<ProcessInfo>,
    local_port: u16,
    local_addr: IpAddr,
    remote_port: Option<u16>,
    remote_addr: Option<IpAddr>,
    protocol: ProtocolFlags,
    state: Option<TcpState>,
    family: AddressFamilyFlags,
}

/// Retrieves sockets for a given address family.
fn get_sockets(sys: &System, addr: AddressFamilyFlags) -> Vec<SocketInfo> {
    let protos = ProtocolFlags::TCP | ProtocolFlags::UDP;
    let iterator = iterate_sockets_info(addr, protos).expect("Failed to get socket information!");

    let mut sockets = Vec::new();

    for info in iterator {
        let si = match info {
            Ok(si) => si,
            Err(_) => continue,
        };

        let processes: Vec<ProcessInfo> = si
            .associated_pids
            .iter()
            .map(|&pid| {
                let pid_obj = Pid::from_u32(pid);
                let name = sys
                    .process(pid_obj)
                    .map_or("".to_string(), |p| p.name().to_string_lossy().into_owned());
                ProcessInfo { pid, name }
            })
            .collect();

        match si.protocol_socket_info {
            ProtocolSocketInfo::Tcp(tcp) => sockets.push(SocketInfo {
                processes,
                local_port: tcp.local_port,
                local_addr: tcp.local_addr,
                remote_port: Some(tcp.remote_port),
                remote_addr: Some(tcp.remote_addr),
                protocol: ProtocolFlags::TCP,
                state: Some(tcp.state),
                family: addr,
            }),
            ProtocolSocketInfo::Udp(udp) => sockets.push(SocketInfo {
                processes,
                local_port: udp.local_port,
                local_addr: udp.local_addr,
                remote_port: None,
                remote_addr: None,
                protocol: ProtocolFlags::UDP,
                state: None,
                family: addr,
            }),
        }
    }

    sockets
}

/// Gets the UID for a given PID using cross-platform sysinfo functionality.
fn get_uid_from_pid(sys: &System, pid: u32) -> Option<u32> {
    let pid_obj = Pid::from_u32(pid);
    sys.process(pid_obj).and_then(|process| {
        // Try to get the user ID from the process
        // The sysinfo crate provides different methods depending on the platform
        #[cfg(unix)]
        {
            // On Unix-like systems (Linux, macOS, etc.), we can use the user_id method
            process.user_id().map(|uid| **uid as u32)
        }
        #[cfg(not(unix))]
        {
            // On non-Unix systems, fallback to None
            None
        }
    })
}

/// Command-line arguments.
#[derive(Parser, Debug)]
#[command(author, version, about = "Lists ports in use and their owning processes", long_about = None)]
struct Args {
    /// Port to filter for (if not provided, lists all ports in a table)
    #[arg(short, long)]
    port: Option<u16>,
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Refresh process information.
    let mut sys = System::new_all();
    sys.refresh_processes(ProcessesToUpdate::All, true);

    // Retrieve sockets for IPv4 and IPv6.
    let mut sockets = get_sockets(&sys, AddressFamilyFlags::IPV4);
    let mut sockets6 = get_sockets(&sys, AddressFamilyFlags::IPV6);
    sockets.append(&mut sockets6);

    // Focus on TCP sockets only.
    let mut tcp_sockets: Vec<SocketInfo> = sockets
        .into_iter()
        .filter(|s| s.protocol == ProtocolFlags::TCP)
        .collect();

    // Closure to map TCP state to a string.
    let state_to_str = |state: &Option<TcpState>| -> String {
        match state {
            Some(TcpState::Listen) => "LISTEN",
            Some(TcpState::SynSent) => "SYN_SENT",
            Some(TcpState::SynReceived) => "SYN_RECEIVED",
            Some(TcpState::Established) => "ESTABLISHED",
            Some(TcpState::FinWait1) => "FIN_WAIT_1",
            Some(TcpState::FinWait2) => "FIN_WAIT_2",
            Some(TcpState::CloseWait) => "CLOSE_WAIT",
            Some(TcpState::Closing) => "CLOSING",
            Some(TcpState::LastAck) => "LAST_ACK",
            Some(TcpState::TimeWait) => "TIME_WAIT",
            Some(TcpState::Closed) => "CLOSED",
            Some(TcpState::DeleteTcb) => "DELETE_TCB",
            Some(TcpState::Unknown) => "UNKNOWN",
            None => "UNKNOWN",
        }
        .to_string()
    };

    if let Some(filter_port) = args.port {
        // Filter for matching sockets.
        let matching: Vec<&SocketInfo> = tcp_sockets
            .iter()
            .filter(|s| s.local_port == filter_port)
            .collect();

        if matching.is_empty() {
            return Err(anyhow::anyhow!("Port {} is not in use.", filter_port));
        } else {
            // Detailed print for each matching socket.
            for s in matching {
                let proto_str = match s.family {
                    AddressFamilyFlags::IPV4 => "TCP",
                    AddressFamilyFlags::IPV6 => "TCP6",
                    _ => "TCP",
                };
                let state_str = state_to_str(&s.state);

                // Use the first associated process (if any).
                let (pid, proc_name) = if let Some(proc_info) = s.processes.first() {
                    (proc_info.pid, proc_info.name.clone())
                } else {
                    (0, "unknown".to_string())
                };

                let uid_str = if pid != 0 {
                    if let Some(uid) = get_uid_from_pid(&sys, pid) {
                        uid.to_string()
                    } else {
                        "unknown".to_string()
                    }
                } else {
                    "unknown".to_string()
                };

                let user = if let Ok(uid_val) = uid_str.parse::<u32>() {
                    get_user_by_uid(uid_val)
                        .map(|u| u.name().to_string_lossy().into_owned())
                        .unwrap_or_else(|| "unknown".to_string())
                } else {
                    "unknown".to_string()
                };

                let local = format!("{}:{}", s.local_addr, s.local_port);
                let remote = if let (Some(raddr), Some(rport)) = (s.remote_addr, s.remote_port) {
                    format!("{}:{}", raddr, rport)
                } else {
                    "-".to_string()
                };

                println!("Port {}/{}:", s.local_port, proto_str);
                println!("  Local Address: {}", local);
                println!("  Remote Address: {}", remote);
                println!("  State: {}", state_str);
                println!("  Process: {} (PID: {})", proc_name, pid);
                println!("  UID: {} (User: {})", uid_str, user);
                println!();
            }
        }
    } else {
        // Sort tcp_sockets in descending order by port.
        tcp_sockets.sort_by(|a, b| a.local_port.cmp(&b.local_port));

        // Print a table of all TCP sockets.
        let mut tw = TabWriter::new(std::io::stdout());
        // Header: PORT, UID, USER, STATUS, PROTOCOL, PROCESS_NAME, LOCAL, REMOTE
        writeln!(
            tw,
            "PORT\tUID\tUSER\tSTATUS\tPROTOCOL\tPROCESS_NAME\tLOCAL\tREMOTE"
        )
        .unwrap();
        for s in tcp_sockets {
            let proto_str = match s.family {
                AddressFamilyFlags::IPV4 => "TCP",
                AddressFamilyFlags::IPV6 => "TCP6",
                _ => "TCP",
            };
            let state_str = state_to_str(&s.state);

            let (pid, proc_name) = if let Some(proc_info) = s.processes.first() {
                (proc_info.pid, proc_info.name.clone())
            } else {
                (0, "unknown".to_string())
            };

            let uid_str = if pid != 0 {
                if let Some(uid) = get_uid_from_pid(&sys, pid) {
                    uid.to_string()
                } else {
                    "unknown".to_string()
                }
            } else {
                "unknown".to_string()
            };

            let user = if let Ok(uid_val) = uid_str.parse::<u32>() {
                get_user_by_uid(uid_val)
                    .map(|u| u.name().to_string_lossy().into_owned())
                    .unwrap_or_else(|| "unknown".to_string())
            } else {
                "unknown".to_string()
            };

            let local = format!("{}:{}", s.local_addr, s.local_port);
            let remote = if let (Some(raddr), Some(rport)) = (s.remote_addr, s.remote_port) {
                format!("{}:{}", raddr, rport)
            } else {
                "-".to_string()
            };

            writeln!(
                tw,
                "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
                s.local_port, uid_str, user, state_str, proto_str, proc_name, local, remote
            )
            .unwrap();
        }
        tw.flush().unwrap();
    }

    Ok(())
}
