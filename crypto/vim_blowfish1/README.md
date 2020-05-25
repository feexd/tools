# Break vim Blowfish1 encryption method

Vim has a security issue with the `blowfish` encryption method because it reuses the first block's
IV in subsequent blocks. This makes possible to retrieve the keystream and decrypt the file as long
as the first 8 bytes of the file are known.

## Usage

To use this script we need the encrypted file and another file with at least the first 8 plain-text
bytes. Then we can run:

`./break_vimbf1.py encrypted_file file_with_first_eight_bytes`


## References
- https://dgl.cx/2014/10/vim-blowfish
