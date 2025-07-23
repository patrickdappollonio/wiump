# wiump - who is using my port?

[![Github Downloads](https://img.shields.io/github/downloads/patrickdappollonio/wiump/total?color=orange&label=github%20downloads)](https://github.com/patrickdappollonio/wiump/releases)

`wiump` is a small app written in Rust to find which process is using a given port. The app scans TCP and UDP ports and returns the process name and PID.

```bash
$ wiump
PORT   PID     UID      USER            STATUS       PROTOCOL  PROCESS_NAME     LOCAL                 REMOTE
53     101     101      systemd-resolve LISTEN       TCP       systemd-resolved 127.0.0.53:53         0.0.0.0:0
80     1234    1000     webdev          LISTEN       TCP       nginx            0.0.0.0:80            0.0.0.0:0
443    1234    1000     webdev          LISTEN       TCP       nginx            0.0.0.0:443           0.0.0.0:0
3000   5678    1000     webdev          LISTEN       TCP       node             127.0.0.1:3000        0.0.0.0:0
5432   999     999      postgres        LISTEN       TCP       postgres         127.0.0.1:5432        0.0.0.0:0
8080   9012    1000     webdev          LISTEN       TCP6      java             :::8080               :::0
22     0       0        root            LISTEN       TCP       sshd             0.0.0.0:22            0.0.0.0:0
```

If provided with a port using `-p` or `--port`, it will display information just for that resource. For example, `wiump -p 3000` will show you that a `node` process is using that port:

```bash
$ wiump --port 3000
Port 3000/TCP:
  Local Address: 127.0.0.1:3000
  Remote Address: 0.0.0.0:0
  State: LISTEN
  Process: node (PID: 5678)
  Command: node server.js
  Executable: /usr/bin/node
  Working Directory: /home/webdev/myapp
  UID: 1000 (User: webdev)
```

Or, for port 53, you'll get the following (note the use of `sudo` to be able to fetch process names from other users):

```bash
$ sudo wiump --port 53
Port 53/TCP:
  Local Address: 127.0.0.53:53
  Remote Address: 0.0.0.0:0
  State: LISTEN
  Process: systemd-resolve (PID: 170)
  UID: 101 (User: systemd-resolve)

Port 53/TCP:
  Local Address: 10.255.255.254:53
  Remote Address: 0.0.0.0:0
  State: LISTEN
  Process: unknown (PID: 0)
  UID: unknown (User: unknown)
```

Seeing `(unknown)` means your user isn't privileged enough to see the process name or one hasn't been reported or we couldn't map the PID to another application except the kernel. You can run `wiump` with `sudo` to get the process name if one should exist and is available to `root`.
