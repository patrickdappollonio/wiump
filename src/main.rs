use anyhow::Result;
use clap::Parser;
use netstat2::{
    AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo, TcpState, iterate_sockets_info,
};
use std::io::Write;
use std::net::IpAddr;
use std::path::PathBuf;
use sysinfo::{Pid, ProcessesToUpdate, System};
use tabwriter::TabWriter;
use users::get_user_by_uid;

/// Simple process info structure.
#[derive(Debug, Clone)]
struct ProcessInfo {
    pid: u32,
    uid: Option<u32>,
    name: String,
    cmd: Vec<String>,
    exe: PathBuf,
    cwd: PathBuf,
}

/// Our unified socket structure.
#[derive(Debug, Clone)]
struct SocketInfo {
    local_port: u16,
    local_addr: IpAddr,
    remote_port: Option<u16>,
    remote_addr: Option<IpAddr>,
    protocol: ProtocolFlags,
    state: Option<TcpState>,
    family: AddressFamilyFlags,
    processes: Vec<ProcessInfo>,
}

/// Retrieves sockets for a given address family.
fn get_sockets(sys: &System, addr: AddressFamilyFlags) -> Result<Vec<SocketInfo>> {
    let protos = ProtocolFlags::TCP | ProtocolFlags::UDP;
    let iterator = iterate_sockets_info(addr, protos)
        .map_err(|e| anyhow::anyhow!("Failed to get socket information: {}", e))?;

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
                if let Some(process) = sys.process(pid_obj) {
                    let name = process.name().to_string_lossy().into_owned();
                    let uid = process.user_id().map(|uid_ref| **uid_ref);
                    let cmd = process
                        .cmd()
                        .iter()
                        .map(|s| s.to_string_lossy().into_owned())
                        .collect();
                    let exe = process.exe().map_or_else(PathBuf::new, |p| p.to_path_buf());
                    let cwd = process.cwd().map_or_else(PathBuf::new, |p| p.to_path_buf());
                    ProcessInfo {
                        pid,
                        uid,
                        name,
                        cmd,
                        exe,
                        cwd,
                    }
                } else {
                    let name = "unknown".to_string();
                    ProcessInfo {
                        pid,
                        uid: None,
                        name,
                        cmd: Vec::new(),
                        exe: PathBuf::new(),
                        cwd: PathBuf::new(),
                    }
                }
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

    Ok(sockets)
}

/// Format command line for display, truncating if too long
fn format_command_line(cmd: &[String], max_length: usize) -> String {
    if cmd.is_empty() {
        return "unknown".to_string();
    }

    let full_cmd = cmd.join(" ");
    if full_cmd.len() <= max_length {
        full_cmd
    } else {
        format!("{}...", &full_cmd[..max_length.saturating_sub(3)])
    }
}

/// Convert TCP state to string representation
fn tcp_state_to_str(state: &Option<TcpState>) -> &'static str {
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
        Some(TcpState::Unknown) | None => "UNKNOWN",
    }
}

/// Get protocol string based on address family
fn get_protocol_string(family: AddressFamilyFlags) -> &'static str {
    match family {
        AddressFamilyFlags::IPV4 => "TCP",
        AddressFamilyFlags::IPV6 => "TCP6",
        _ => "TCP",
    }
}

/// Format remote address for display
fn format_remote_address(remote_addr: Option<IpAddr>, remote_port: Option<u16>) -> String {
    if let (Some(raddr), Some(rport)) = (remote_addr, remote_port) {
        format!("{raddr}:{rport}")
    } else {
        "-".to_string()
    }
}

/// Get user information from UID
fn get_user_info(uid: Option<u32>) -> (String, String) {
    let uid_str = uid.map_or_else(|| "unknown".to_string(), |uid| uid.to_string());
    let user = uid
        .and_then(get_user_by_uid)
        .map(|u| u.name().to_string_lossy().into_owned())
        .unwrap_or_else(|| "unknown".to_string());
    (uid_str, user)
}

/// Command-line arguments.
#[derive(Parser, Debug)]
#[command(author, version, about = "Lists ports in use and their owning processes", long_about = None)]
struct Args {
    /// Port to filter for (if not provided, lists all ports in a table)
    #[arg(short, long)]
    port: Option<u16>,

    /// Show detailed process information in table view
    #[arg(short, long)]
    detailed: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Refresh process information.
    let mut sys = System::new_all();
    sys.refresh_processes(ProcessesToUpdate::All, true);

    // Retrieve sockets for IPv4 and IPv6.
    let mut sockets = get_sockets(&sys, AddressFamilyFlags::IPV4)?;
    let mut sockets6 = get_sockets(&sys, AddressFamilyFlags::IPV6)?;
    sockets.append(&mut sockets6);

    // Focus on TCP sockets only.
    let mut tcp_sockets: Vec<SocketInfo> = sockets
        .into_iter()
        .filter(|s| s.protocol == ProtocolFlags::TCP)
        .collect();

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
                let proto_str = get_protocol_string(s.family);
                let state_str = tcp_state_to_str(&s.state);

                // Use the first associated process (if any).
                let (pid, proc_name, uid_opt, cmd, exe, cwd) =
                    if let Some(proc_info) = s.processes.first() {
                        (
                            proc_info.pid,
                            proc_info.name.clone(),
                            proc_info.uid,
                            &proc_info.cmd,
                            &proc_info.exe,
                            &proc_info.cwd,
                        )
                    } else {
                        (
                            0,
                            "unknown".to_string(),
                            None,
                            &Vec::new(),
                            &PathBuf::new(),
                            &PathBuf::new(),
                        )
                    };

                let (uid_str, user) = get_user_info(uid_opt);

                let local = format!("{}:{}", s.local_addr, s.local_port);
                let remote = format_remote_address(s.remote_addr, s.remote_port);

                println!("Port {}/{}:", s.local_port, proto_str);
                println!("  Local Address: {local}");
                println!("  Remote Address: {remote}");
                println!("  State: {state_str}");
                let display_name = if pid == 0 && proc_name == "unknown" {
                    "unknown, likely a \"kernel\" process"
                } else {
                    &proc_name
                };
                println!("  Process: {display_name} (PID: {pid})");

                // Show detailed process information
                if !cmd.is_empty() {
                    println!("  Command: {}", cmd.join(" "));
                }
                if !exe.as_os_str().is_empty() {
                    println!("  Executable: {}", exe.display());
                }
                if !cwd.as_os_str().is_empty() {
                    println!("  Working Directory: {}", cwd.display());
                }

                let display_user = if pid == 0 && user == "unknown" {
                    "unknown, likely \"kernel\""
                } else {
                    &user
                };
                println!("  UID: {uid_str} (User: {display_user})");
                println!();
            }
        }
    } else {
        // Sort tcp_sockets in descending order by port.
        tcp_sockets.sort_by(|a, b| a.local_port.cmp(&b.local_port));

        // Print a table of all TCP sockets.
        let mut tw = TabWriter::new(std::io::stdout());

        if args.detailed {
            // Header with detailed information
            writeln!(
                tw,
                "PORT\tPID\tUID\tUSER\tSTATUS\tPROTOCOL\tPROCESS_NAME\tCOMMAND\tLOCAL\tREMOTE"
            )
            .map_err(|e| anyhow::anyhow!("Failed to write to output: {}", e))?;
            for s in tcp_sockets {
                let proto_str = get_protocol_string(s.family);
                let state_str = tcp_state_to_str(&s.state);

                let (pid, proc_name, uid_opt, cmd) = if let Some(proc_info) = s.processes.first() {
                    (
                        proc_info.pid,
                        proc_info.name.clone(),
                        proc_info.uid,
                        &proc_info.cmd,
                    )
                } else {
                    (0, "unknown".to_string(), None, &Vec::new())
                };

                let (uid_str, user) = get_user_info(uid_opt);

                let local = format!("{}:{}", s.local_addr, s.local_port);
                let remote = format_remote_address(s.remote_addr, s.remote_port);

                let command_display = format_command_line(cmd, 40);

                writeln!(
                    tw,
                    "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
                    s.local_port,
                    pid,
                    uid_str,
                    user,
                    state_str,
                    proto_str,
                    proc_name,
                    command_display,
                    local,
                    remote
                )
                .map_err(|e| anyhow::anyhow!("Failed to write to output: {}", e))?;
            }
        } else {
            // Header: PORT, PID, UID, USER, STATUS, PROTOCOL, PROCESS_NAME, LOCAL, REMOTE
            writeln!(
                tw,
                "PORT\tPID\tUID\tUSER\tSTATUS\tPROTOCOL\tPROCESS_NAME\tLOCAL\tREMOTE"
            )
            .map_err(|e| anyhow::anyhow!("Failed to write to output: {}", e))?;
            for s in tcp_sockets {
                let proto_str = get_protocol_string(s.family);
                let state_str = tcp_state_to_str(&s.state);

                let (pid, proc_name, uid_opt) = if let Some(proc_info) = s.processes.first() {
                    (proc_info.pid, proc_info.name.clone(), proc_info.uid)
                } else {
                    (0, "unknown".to_string(), None)
                };

                let (uid_str, user) = get_user_info(uid_opt);

                let local = format!("{}:{}", s.local_addr, s.local_port);
                let remote = format_remote_address(s.remote_addr, s.remote_port);

                writeln!(
                    tw,
                    "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
                    s.local_port, pid, uid_str, user, state_str, proto_str, proc_name, local, remote
                )
                .map_err(|e| anyhow::anyhow!("Failed to write to output: {}", e))?;
            }
        }
        tw.flush()
            .map_err(|e| anyhow::anyhow!("Failed to flush output: {}", e))?;
    }

    Ok(())
}
