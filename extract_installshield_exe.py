#!/usr/bin/env python3

import os
import struct
import sys
from pathlib import Path, PureWindowsPath

machines = {
    0: "unknown",
    0x014C: "Intel i386",
    0x014D: "Intel i486",
    0x014E: "Intel i586",
    0x0160: "MIPS R3000 (big-endian)",
    0x0162: "MIPS R3000 (little-endian)",
    0x0166: "MIPS R4000 (little-endian)",
    0x0168: "MIPS R10000 (little-endian)",
    0x0169: "MIPS WCE v2 (little-endian)",
    0x0184: "Alpha",
    0x01A2: "SH-3 (little-endian)",
    0x01A3: "SH-3 DSP",
    0x01A4: "SH-3E",
    0x01A6: "SH-4 (little-endian)",
    0x01A8: "SH-5 (little-endian)",
    0x01C0: "Arm (little-endian)",
    0x01C2: "Arm Thumb/Thumb-2 (little-endian)",
    0x01C4: "Arm Thumb-2 (little-endian)",
    0x01d3: "TAM33BD",
    0x01F0: "IBM Power PC",
    0x01F1: "IBM Power PC FP",
    0x0200: "IA64 Itanium",
    0x0266: "MIPS16",
    0x0284: "Alpha 64",
    0x0366: "MIPS FPU",
    0x0466: "MIPS FPU16",
    0x0520: "Infineon Tricore",
    0x0CEF: "CEF",
    0x0EBC: "EFI byte code",
    0x8664: "AMD64 (K8)",
    0x9041: "M32R (little-endian)",
    0xAA64: "Arm 64 (little-endian)",
    0xC0EE: "C0EE",
}


def get_machine(m):
    try:
        return f"{hex(m)} ({machines[m]})"
    except KeyError:
        return f"{hex(m)} (UNKNOWN)"


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
    (pe_sig, machine, number_of_sections, size_of_optional_header) = struct.unpack('<lHH12xH2x', bytes_read)

    print(f"machine: {get_machine(machine)}")

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
    print(f"size_of_raw_data: {size_of_raw_data} [{hex(size_of_raw_data)}]")
    print(f"pointer_to_raw_data: {pointer_to_raw_data} [{hex(pointer_to_raw_data)}]")
    resource_data_addr = pointer_to_raw_data + size_of_raw_data
    print(f"resource_data_addr: {resource_data_addr} [{hex(resource_data_addr)}]")
    return machine, resource_data_addr


def read_to_string_w(fp):
    bytes_read = fp.read(2)
    ret = ""
    while bytes_read != b'\0\0':
        ret += str(bytes_read, 'utf-16')
        bytes_read = fp.read(2)

    return None if ret == "" else ret


def read_to_string(fp):
    bytes_read = fp.read(1)
    ret = ""
    while bytes_read != b'\0':
        ret += str(bytes_read, 'utf-8')
        bytes_read = fp.read(1)

    return None if ret == "" else ret


def get_attributes(fp, data_offset: int, read_to_string) -> (str, str, str, int, int):
    """
    Read a file entry and return its values.
    :param fp: file pointer
    :param data_offset: data offset from which to read file entries
    :param read_to_string: string read function
    :return: tuple of filename, destination file name, file version, file length, data offset after reading
    """
    try:
        fp.seek(data_offset)
        filename = read_to_string(fp)
        destination_name = read_to_string(fp)
        version = read_to_string(fp)
        filelen = read_to_string(fp)
        print(f"filename: {filename}, destination_name: {destination_name}, version: {version}, file length: {filelen}")
        flen = int(filelen) if filelen is not None else None
        off = fp.tell() if filename is not None and flen is not None else data_offset
        return filename, destination_name, version, flen, off
    except ValueError:
        return None, None, None, None, data_offset


def extract_plain_files(fp, data_offset, read_to_str) -> int:
    """
    Extract and save files.
    :param fp: file pointer
    :param data_offset: data offset from which to extract files
    :param read_to_str: string read function
    :return: data offset after extraction
    """
    off = data_offset
    try:
        (name, dest, ver, len, off) = get_attributes(fp, off, read_to_str)
        while name is not None and len is not None:
            # save file
            filename = Path(PureWindowsPath(dest))  # fix for windows path
            os.makedirs(os.path.dirname(filename), exist_ok=True)
            with open(filename, 'wb') as out:
                fp.seek(off)
                read_bytes = fp.read(len)
                out.write(read_bytes)
            (name, dest, ver, len, off) = get_attributes(fp, off + len, read_to_str)
        return off
    except UnicodeDecodeError:
        # no more files
        return off


def get_file_length(filename: str):
    try:
        stat = os.stat(filename)
        return stat.st_size
    except FileNotFoundError as e:
        print(e)
        return None


if len(sys.argv) < 2:
    print("filename required.")
    exit(1)

filelen = get_file_length(sys.argv[1])

if filelen is None:
    exit(1)

with open(sys.argv[1], "rb") as fp:
    (machine, offset) = get_data_offset(fp)
    if 0 <= offset >= filelen:
        print(f"error: invalid file: offset={offset}, file size={filelen}")
        exit(1)

    offset = offset + 4
    fp.seek(offset)
    if extract_plain_files(fp, offset, read_to_string_w) == offset:
        print("not plain wide files")

    fp.seek(offset)
    if extract_plain_files(fp, offset, read_to_string) == offset:
        print("not plain files")
        exit(1)
