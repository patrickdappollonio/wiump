# wiump - who is using my port?

`wiump` is a small app written in Rust to find which process is using a given port. The app scans TCP and UDP ports and returns the process name and PID.

```bash
$ wiump
PORT   UID      USER             STATUS       PROTOCOL  PROCESS_NAME     LOCAL                REMOTE
53     101      systemd-resolve  LISTEN       TCP       systemd-resolve  127.0.0.53:53        0.0.0.0:0
53     unknown  unknown          LISTEN       TCP       unknown          10.255.255.254:53    0.0.0.0:0
5000   1000     patrick          LISTEN       TCP6      http-server      :::5000              :::0
35972  1000     patrick          ESTABLISHED  TCP       node             127.0.0.1:35972      127.0.0.1:39945
35976  1000     patrick          ESTABLISHED  TCP       node             127.0.0.1:35976      127.0.0.1:39945
39945  1000     patrick          LISTEN       TCP       node             127.0.0.1:39945      0.0.0.0:0
39945  1000     patrick          ESTABLISHED  TCP       node             127.0.0.1:39945      127.0.0.1:35972
39945  1000     patrick          ESTABLISHED  TCP       node             127.0.0.1:39945      127.0.0.1:35976
```

If provided with a port using `-p` or `--port`, it will display information just for that resource. For example, `wiump -p 5000` will show you that my [`http-server`](https://github.com/patrickdappollonio/http-server) is using that port:

```bash
$ wiump --port 5000
Port 5000/TCP6:
  Local Address: :::5000
  Remote Address: :::0
  State: LISTEN
  Process: http-server (PID: 7386)
  UID: 1000 (User: patrick)
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

> [!WARNING]
> Not all features are available on macOS. This application is more Linux friendly.

**Learning experience**

This app was made as a way to learn about Rust and how to use it to build a CLI app. There might be bugs or non-idiomatic ways of doing things. If so, please do let me know! I'm available on Twitter, Mastodon, BlueSky and a few other places. My profile contains all the links.
