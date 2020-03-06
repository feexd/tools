#!/usr/bin/env python3
# -*- coding: latin-1 -*-

# Taken from: https://github.com/smorin/hextool/blob/master/hexdump.py

# <-- removing this magic comment breaks Python 3.4 on Windows
"""
1. Dump binary data to the following text format:

00000000: 00 00 00 5B 68 65 78 64  75 6D 70 5D 00 00 00 00  ...[hexdump]....
00000010: 00 11 22 33 44 55 66 77  88 99 AA BB CC DD EE FF  .."3DUfw........

It is similar to the one used by:
Scapy
00 00 00 5B 68 65 78 64 75 6D 70 5D 00 00 00 00  ...[hexdump]....
00 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF  .."3DUfw........

Far Manager
000000000: 00 00 00 5B 68 65 78 64 ¦ 75 6D 70 5D 00 00 00 00     [hexdump]
000000010: 00 11 22 33 44 55 66 77 ¦ 88 99 AA BB CC DD EE FF   ?"3DUfwª»ÌÝîÿ


2. Restore binary data from the formats above as well
   as from less exotic strings of raw hex

"""

__version__ = '3.4dev'
__author__  = 'anatoly techtonik <techtonik@gmail.com>'
__license__ = 'Public Domain'

__history__ = \
"""
3.4 (WIP)
 * support more dump formats for restore() by better
   detection of column separator - now dumps with
   unicode separator U+2502 are also supported
 * another fix for Python 3, which is too smart -
   opens dumps in system encoding (which can be any)
   and fails to read dump if its encoding differs
 * add restore() testdata for various dump formats
 * add license file for packagers (issue #3)

3.3 (2015-01-22)
 * accept input from sys.stdin if "-" is specified
   for both dump and restore (issue #1)
 * new normalize_py() helper to set sys.stdout to
   binary mode on Windows

3.2 (2015-07-02)
 * hexdump is now packaged as .zip on all platforms
   (on Linux created archive was tar.gz)
 * .zip is executable! try `python hexdump-3.2.zip`
 * dump() now accepts configurable separator, patch
   by Ian Land (PR #3)

3.1 (2014-10-20)
 * implemented workaround against mysterious coding
   issue with Python 3 (see revision 51302cf)
 * fix Python 3 installs for systems where UTF-8 is
   not default (Windows), thanks to George Schizas
   (the problem was caused by reading of README.txt)

3.0 (2014-09-07)
 * remove unused int2byte() helper
 * add dehex(text) helper to convert hex string
   to binary data
 * add 'size' argument to dump() helper to specify
   length of chunks

2.0 (2014-02-02)
 * add --restore option to command line mode to get
   binary data back from hex dump
 * support saving test output with `--test logfile`
 * restore() from hex strings without spaces
 * restore() now raises TypeError if input data is
   not string
 * hexdump() and dumpgen() now don't return unicode
   strings in Python 2.x when generator is requested

1.0 (2013-12-30)
 * length of address is reduced from 10 to 8
 * hexdump() got new 'result' keyword argument, it
   can be either 'print', 'generator' or 'return'
 * actual dumping logic is now in new dumpgen()
   generator function
 * new dump(binary) function that takes binary data
   and returns string like "66 6F 72 6D 61 74"
 * new genchunks(mixed, size) function that chunks
   both sequences and file like objects

0.5 (2013-06-10)
 * hexdump is now also a command line utility (no
   restore yet)

0.4 (2013-06-09)
 * fix installation with Python 3 for non English
   versions of Windows, thanks to George Schizas

0.3 (2013-04-29)
 * fully Python 3 compatible

0.2 (2013-04-28)
 * restore() to recover binary data from a hex dump in
   native, Far Manager and Scapy text formats (others
   might work as well)
 * restore() is Python 3 compatible

0.1 (2013-04-28)
 * working hexdump() function for Python 2
"""

import binascii  # binascii is required for Python 3
import sys

# --- constants
PY3K = sys.version_info >= (3, 0)

# --- workaround against Python consistency issues
def normalize_py():
  ''' Problem 001 - sys.stdout in Python is by default opened in
      text mode, and writes to this stdout produce corrupted binary
      data on Windows

          python -c "import sys; sys.stdout.write('_\n_')" > file
          python -c "print(repr(open('file', 'rb').read()))"
  '''
  if sys.platform == "win32":
    # set sys.stdout to binary mode on Windows
    import os, msvcrt
    msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)

# --- - chunking helpers
def chunks(seq, size):
  '''Generator that cuts sequence (bytes, memoryview, etc.)
     into chunks of given size. If `seq` length is not multiply
     of `size`, the lengh of the last chunk returned will be
     less than requested.

     >>> list( chunks([1,2,3,4,5,6,7], 3) )
     [[1, 2, 3], [4, 5, 6], [7]]
  '''
  d, m = divmod(len(seq), size)
  for i in range(d):
    yield seq[i*size:(i+1)*size]
  if m:
    yield seq[d*size:]

def chunkread(f, size):
  '''Generator that reads from file like object. May return less
     data than requested on the last read.'''
  c = f.read(size)
  while len(c):
    yield c
    c = f.read(size)

def genchunks(mixed, size):
  '''Generator to chunk binary sequences or file like objects.
     The size of the last chunk returned may be less than
     requested.'''
  if hasattr(mixed, 'read'):
    return chunkread(mixed, size)
  else:
    return chunks(mixed, size)
# --- - /chunking helpers


def dehex(hextext):
  """
  Convert from hex string to binary data stripping
  whitespaces from `hextext` if necessary.
  """
  if PY3K:
    return bytes.fromhex(hextext)
  else:
    hextext = "".join(hextext.split())
    return hextext.decode('hex')

def dump(binary, size=2, sep=' '):
  '''
  Convert binary data (bytes in Python 3 and str in
  Python 2) to hex string like '00 DE AD BE EF'.
  `size` argument specifies length of text chunks
  and `sep` sets chunk separator.
  '''
  hexstr = binascii.hexlify(binary)
  if PY3K:
    hexstr = hexstr.decode('ascii')
  return sep.join(chunks(hexstr.upper(), size))

def dumpgen(data):
  '''
  Generator that produces strings:

  '00000000: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................'
  '''
  generator = genchunks(data, 16)
  for addr, d in enumerate(generator):
    # 00000000:
    line = '%08X: ' % (addr*16)
    # 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00 
    dumpstr = dump(d)
    line += dumpstr[:8*3]
    if len(d) > 8:  # insert separator if needed
      line += ' ' + dumpstr[8*3:]
    # ................
    # calculate indentation, which may be different for the last line
    pad = 2
    if len(d) < 16:
      pad += 3*(16 - len(d))
    if len(d) <= 8:
      pad += 1
    line += ' '*pad

    for byte in d:
      # printable ASCII range 0x20 to 0x7E
      if not PY3K:
        byte = ord(byte)
      if 0x20 <= byte <= 0x7E:
        line += chr(byte)
      else:
        line += '.'
    yield line
  
def hexdump(data, result='print'):
  '''
  Transform binary data to the hex dump text format:

  00000000: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................

    [x] data argument as a binary string
    [x] data argument as a file like object

  Returns result depending on the `result` argument:
    'print'     - prints line by line
    'return'    - returns single string
    'generator' - returns generator that produces lines
  '''
  if PY3K and type(data) == str:
    raise TypeError('Abstract unicode data (expected bytes sequence)')

  gen = dumpgen(data)
  if result == 'generator':
    return gen
  elif result == 'return':
    return '\n'.join(gen)
  elif result == 'print':
    for line in gen:
      print(line)
  else:
    raise ValueError('Unknown value of `result` argument')

def restore(dump):
  '''
  Restore binary data from a hex dump.
    [x] dump argument as a string
    [ ] dump argument as a line iterator

  Supported formats:
    [x] hexdump.hexdump
    [x] Scapy
    [x] Far Manager
  '''
  minhexwidth = 2*16    # minimal width of the hex part - 00000... style
  bytehexwidth = 3*16-1 # min width for a bytewise dump - 00 00 ... style

  result = bytes() if PY3K else ''
  if type(dump) != str:
    raise TypeError('Invalid data for restore')

  text = dump.strip()  # ignore surrounding empty lines
  dumptype = None
  for line in text.split('\n'):
    # strip address part
    addrend = line.find(':')
    if 0 < addrend < minhexwidth:  # : is not in ascii part
      line = line[addrend+1:]
    line = line.lstrip()
    # check dump type
    if line[2] == ' ':  # 00 00 00 ...  type of dump
      # calculate separator position
      sepstart = (2+1)*8  # ('00'+' ')*8
      sep = line[sepstart:sepstart+3]
      if sep[0] == ' ' and sep[1] != ' ':
        # ...00 00  00 00...
        dumptype = "doublespaced"
        hexdata = line[:bytehexwidth+1]
      elif sep[1] == ' ':
        # ...00 00 | 00 00...  - Far Manager
        dumptype = "singlebytesep"
        hexdata = line[:sepstart-1] + line[sepstart+2:bytehexwidth+3]
      elif sep == '\xe2\x94\x82':
        # ...00 00 \xe2\x94\x82 00 00...  - Far Manager (utf-8)
        dumptype = "unicodesep"
        hexdata = line[:sepstart-1] + line[sepstart+4:bytehexwidth+5]
      else:
        # ...00 00 00 00... - Scapy, no separator
        dumptype = "nosep"
        hexdata = line[:bytehexwidth]
      line = hexdata
    result += dehex(line)
  return result
