# wiump - who is using my port?

`wiump` is a small app written in Rust to find which process is using a given port. The app scans TCP and UDP ports and returns the process name and PID.

If provided with a port using `-p` or `--port`, it will display information just for that resource. For example, `wiump -p 5000` will show you that my [`http-server`](https://github.com/patrickdappollonio/http-server) is using that port:

```bash
Port 5000/TCP6 is used by process http-server (PID: 82258) with status LISTEN
```

Or, for port 53, you'll get:

```bash
$ wiump -p 53
More than one process reported using port 53
 - Port 53/TCP is used by process (unknown process) with status LISTEN
 - Port 53/UDP is used by process (unknown process)
```

Seeing `(unknown process)` means your user isn't privileged enough to see the process name. You can run `wiump` with `sudo` to get the process name.

**Learning experience**

This app was made as a way to learn about Rust and how to use it to build a CLI app. There might be bugs or non-idiomatic ways of doing things. If so, please do let me know! I'm available on Twitter, Mastodon, BlueSky and a few other places. My profile contains all the links.
