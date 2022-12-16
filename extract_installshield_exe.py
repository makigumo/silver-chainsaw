#!/usr/bin/env python3

import os
import struct
import sys
from pathlib import Path, PureWindowsPath


def get_data_offset(f):
    # read dos header (64 bytes)

    bytes_read = f.read(64)
    # 2 bytes, 58 bytes, 4 bytes
    (e_magic, e_lfanew) = struct.unpack('<H58xl', bytes_read)

    if e_magic != 0x5A4D:
        print("no dos header")
        return 0

    # read pe header (24 bytes)
    f.seek(e_lfanew)
    bytes_read = f.read(24)
    # 4 bytes, 2 bytes, 2 bytes
    (pe_sig, number_of_sections, size_of_optional_header) = struct.unpack('<l2xH12xH2x', bytes_read)

    if pe_sig != 0x4550:
        print("no pe header")
        return 0

    print(f"number_of_sections: {number_of_sections}")
    print(f"size_of_optional_header: {size_of_optional_header}")

    # read optional header, typical 96 + 16 * 8 = 224 bytes
    f.read(size_of_optional_header)
    #  goto last section table
    f.seek((number_of_sections - 1) * 40, 1)
    # read image section header (40 bytes)
    bytes_read = f.read(40)
    (name, size_of_raw_data, pointer_to_raw_data) = struct.unpack('<8s8xll16x', bytes_read)
    print(f"name: {name}")
    print(f"size_of_raw_data: {size_of_raw_data}")
    print(f"pointer_to_raw_data: {pointer_to_raw_data}")

    return pointer_to_raw_data + size_of_raw_data


def read_to_string(fp):
    bytes = fp.read(2)
    ret = ""
    while bytes != b'\0\0':
        ret += str(bytes, 'utf-16')
        bytes = fp.read(2)

    return None if ret == "" else ret


def get_attributes(fp, data_offset):
    # file attributes
    fp.seek(data_offset)
    filename = read_to_string(fp)
    destination_name = read_to_string(fp)
    version = read_to_string(fp)
    filelen = read_to_string(fp)
    print(f"filename: {filename}, destination_name: {destination_name}, version: {version}, file length: {filelen}")
    return filename, destination_name, version, int(filelen), fp.tell() if filename != "" else data_offset


def extract_plain_files_w(fp, data_offset) -> int:
    try:
        (name, dest, ver, len, off) = get_attributes(fp, data_offset)
        while name is not None:
            # save file
            filename = Path(PureWindowsPath(dest))  # fix for windows path
            os.makedirs(os.path.dirname(filename), exist_ok=True)
            with open(filename, 'wb') as out:
                fp.seek(off)
                read_bytes = fp.read(len)
                out.write(read_bytes)
            (name, dest, ver, len, off) = get_attributes(fp, off + len)
        return off
    except UnicodeDecodeError:
        # no more files
        return off


if len(sys.argv) < 2:
    print("filename required.")
    exit(1)

stat = os.stat(sys.argv[1])
filelen = stat.st_size

with open(sys.argv[1], "rb") as fp:
    offset = get_data_offset(fp)
    if 0 <= offset >= filelen:
        print(f"error: invalid file: offset={offset}, file size={filelen}")
        exit(1)

    offset = offset + 4
    fp.seek(offset)
    if extract_plain_files_w(fp, offset) == offset:
        print("not plain wide files")
        exit(1)
