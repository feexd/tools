# Initrd backdoor

These are proof of concepts for infecting Linux `initrd` images with a backdoor. This is useful when
performing Evil maid attacks against Linux machines with full disk encryption that don't encrypt
`/boot` partition and do not have secure boot enabled, which is kind of the default.

# How does it work

The idea is to mount the unencrypted `/boot` partition using a LiveCD or any root shell, extract the
`initrd` image (which is a `cpio` archive) and insert a call to a shell script of our choosing right
after the root partition is available. Next time the user boots the machine they'll unlock the disk
and our script gets executed.

# Implementations

Since this whole `initrd` business is heavily distribution dependent the shell scripts vary wildly
from distro to distro. This is why there's an different implementation for `Debian`, `Ubuntu` and
`Arch Linux`.
