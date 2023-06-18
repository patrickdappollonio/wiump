use std::collections::HashMap;
use std::fs;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

#[derive(Debug)]
struct PortInfo {
    port: u16,
    uid: u32,
    user: String,
    status: String,
    inode: u32,
    protocol: String,
    process_name: Option<String>,
}

fn main() -> std::io::Result<()> {
    let port_infos = get_used_ports()?;
    for info in port_infos {
        println!("{:?}", info);
    }
    Ok(())
}

fn get_used_ports() -> std::io::Result<Vec<PortInfo>> {
    let tcp_status_map = tcp_status_map();
    let user_map = get_user_map()?;
    let mut ports = Vec::new();

    let files = vec![
        ("/proc/net/tcp", "TCP"),
        ("/proc/net/tcp6", "TCP6"),
        ("/proc/net/udp", "UDP"),
        ("/proc/net/udp6", "UDP6"),
    ];

    for (file, protocol) in files {
        let file = File::open(file)?;
        let reader = BufReader::new(file);
        for (index, line) in reader.lines().enumerate() {
            if index == 0 {
                continue;
            }
            let line = line?;
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 10 {
                continue;
            }

            let local_address = fields[1];
            let state = fields[3];
            let uid_str = fields[7];
            let inode_str = fields[9];

            let local_port_hex = local_address.split(':').collect::<Vec<&str>>()[1];
            let local_port = u16::from_str_radix(local_port_hex, 16).ok().unwrap_or(0);

            let uid = uid_str.parse::<u32>().unwrap_or(0);
            let user = user_map
                .get(&uid)
                .cloned()
                .unwrap_or_else(|| "unknown".to_string());

            let inode = inode_str.parse::<u32>().unwrap_or(0);
            let process_name = get_process_name_by_inode(inode);

            let status = if protocol.starts_with("TCP") {
                tcp_status_map.get(state).unwrap_or(&"UNKNOWN").to_string()
            } else {
                "".to_string()
            };

            let port_info = PortInfo {
                port: local_port,
                uid,
                user,
                status,
                inode,
                protocol: protocol.to_string(),
                process_name,
            };

            ports.push(port_info);
        }
    }

    Ok(ports)
}

fn tcp_status_map() -> HashMap<&'static str, &'static str> {
    let mut m = HashMap::new();
    m.insert("01", "ESTABLISHED");
    m.insert("02", "SYN_SENT");
    m.insert("03", "SYN_RECV");
    m.insert("04", "FIN_WAIT1");
    m.insert("05", "FIN_WAIT2");
    m.insert("06", "TIME_WAIT");
    m.insert("07", "CLOSE");
    m.insert("08", "CLOSE_WAIT");
    m.insert("09", "LAST_ACK");
    m.insert("0A", "LISTEN");
    m.insert("0B", "CLOSING");
    m
}

fn get_user_map() -> std::io::Result<HashMap<u32, String>> {
    let mut user_map = HashMap::new();
    let contents = fs::read_to_string("/etc/passwd")?;
    for line in contents.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() < 3 {
            continue;
        }
        let uid_str = fields[2];
        let uid = uid_str.parse::<u32>().unwrap_or(0);
        user_map.insert(uid, fields[0].to_string());
    }
    Ok(user_map)
}

fn get_process_name_by_inode(inode: u32) -> Option<String> {
    let proc_path = Path::new("/proc");
    if !proc_path.exists() || !proc_path.is_dir() {
        return None;
    }

    let subdirs = proc_path.read_dir().ok()?;

    for dir in subdirs {
        let dir = dir.ok()?;
        if !dir.file_type().ok()?.is_dir() {
            continue;
        }

        let pid_str = dir.file_name().into_string().ok()?;
        let fd_path = format!("/proc/{}/fd", pid_str);
        let files = match Path::new(&fd_path).read_dir() {
            Ok(fds) => fds,
            Err(_) => continue,
        };

        for fd in files {
            let fd = fd.ok()?;
            let rp = fd.path().read_link().ok()?;
            match rp.to_str()?.contains(&format!("socket:[{}]", inode)) {
                true => return get_process_name(&pid_str),
                false => continue,
            }
        }
    }
    None
}

fn get_process_name(pid_str: &str) -> Option<String> {
    let path = format!("/proc/{}/cmdline", pid_str);
    if let Ok(contents) = fs::read_to_string(&path) {
        let process_name = contents.split('\0').next()?;
        return Some(process_name.to_string());
    }
    None
}
