#!/usr/bin/env python3
"""
senandika.py
A small Linux x86_64 shellcode generator for CTF/lab payload prototyping.

Payload behavior:
    write(1, message, len(message))
    exit(0)

Features:
    - custom message
    - optional XOR encoding for message bytes
    - badchar scanner
    - output as raw, python, c, nasm, or asm file
"""

from __future__ import annotations

import argparse
import pathlib
import struct
import sys
from dataclasses import dataclass


DEFAULT_BADCHARS = bytes([0x00, 0x0a, 0x0d])


@dataclass
class BuildResult:
    shellcode: bytes
    message: bytes
    encoded_message: bytes
    key: int | None
    badchars: bytes


def parse_hex_byte(value: str) -> int:
    value = value.strip().lower()
    if value.startswith("0x"):
        value = value[2:]
    if len(value) == 0 or len(value) > 2:
        raise argparse.ArgumentTypeError(f"invalid byte: {value!r}")
    try:
        n = int(value, 16)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid byte: {value!r}") from exc
    if not 0 <= n <= 0xFF:
        raise argparse.ArgumentTypeError(f"byte out of range: {value!r}")
    return n


def parse_badchars(value: str) -> bytes:
    if value.strip() == "":
        return b""
    return bytes(parse_hex_byte(part) for part in value.split(","))


def xor_bytes(data: bytes, key: int) -> bytes:
    return bytes(b ^ key for b in data)


def badchar_hits(data: bytes, badchars: bytes) -> list[tuple[int, int]]:
    bad = set(badchars)
    return [(i, b) for i, b in enumerate(data) if b in bad]


def fmt_hex(data: bytes) -> str:
    return "".join(f"\\x{b:02x}" for b in data)


def fmt_c_array(data: bytes, name: str = "sc") -> str:
    body = ", ".join(f"0x{b:02x}" for b in data)
    return f"unsigned char {name}[] = {{ {body} }};\nunsigned int {name}_len = {len(data)};"


def fmt_python(data: bytes, name: str = "sc") -> str:
    return f'{name} = b"{fmt_hex(data)}"\nprint(len({name}))'


def load_template() -> str:
    here = pathlib.Path(__file__).resolve().parent
    tpl = here / "templates" / "write_exit.asm.tpl"
    return tpl.read_text(encoding="utf-8")


def render_asm(message: bytes, key: int | None) -> str:
    encoded = xor_bytes(message, key) if key is not None else message
    msg_bytes = ", ".join(f"0x{b:02x}" for b in encoded)
    key_line = f"%define XOR_KEY 0x{key:02x}" if key is not None else "%define XOR_KEY 0"
    decode_flag = "1" if key is not None else "0"
    return (
        load_template()
        .replace("{{KEY_DEFINE}}", key_line)
        .replace("{{DECODE_FLAG}}", decode_flag)
        .replace("{{MSG_BYTES}}", msg_bytes)
        .replace("{{MSG_LEN}}", str(len(message)))
        .replace("{{XOR_LINE}}", f"    xor al, 0x{key:02x}" if key is not None else "    ; no xor key")
    )


def build_static_shellcode(message: bytes, key: int | None) -> BuildResult:
    """
    Build raw shellcode directly, no assembler needed.

    Layout:
        jmp short msg
    code:
        pop rsi
        optional decode loop over message
        write syscall
        exit syscall
    msg:
        call code
        db encoded_message
    """
    if len(message) == 0:
        raise ValueError("message must not be empty")
    if len(message) > 255:
        raise ValueError("message too long for compact generator; max 255 bytes")

    encoded = xor_bytes(message, key) if key is not None else message
    n = len(message)

    code = bytearray()
    code += b"\xeb"  # jmp short msg_stub
    # placeholder jump distance
    code += b"\x00"

    code_start = len(code)
    code += b"\x5e"                  # pop rsi

    if key is not None:
        # xor byte [rsi+rcx-1], key loop, using cl=len
        code += b"\x31\xc9"          # xor ecx, ecx
        code += b"\xb1" + bytes([n]) # mov cl, len
        loop_start = len(code)
        code += b"\x80\x74\x0e\xff" + bytes([key])  # xor byte [rsi+rcx-1], key
        code += b"\xe2" + bytes([(loop_start - (len(code) + 2)) & 0xff]) # loop loop_start

    code += b"\xb0\x01"              # mov al, 1 ; write
    code += b"\x40\xb7\x01"          # mov dil, 1
    code += b"\xb2" + bytes([n])      # mov dl, len
    code += b"\x0f\x05"              # syscall
    code += b"\xb0\x3c"              # mov al, 60 ; exit
    code += b"\x31\xff"              # xor edi, edi
    code += b"\x0f\x05"              # syscall

    call_pos = len(code)
    rel = code_start - (call_pos + 5)
    code += b"\xe8" + struct.pack("<i", rel) # call code_start
    code += encoded

    # patch initial jmp to call stub
    code[1] = (call_pos - 2) & 0xff

    return BuildResult(
        shellcode=bytes(code),
        message=message,
        encoded_message=encoded,
        key=key,
        badchars=DEFAULT_BADCHARS,
    )


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(
        prog="senandika",
        description="Linux x86_64 write/exit shellcode generator for CTF/lab use.",
    )
    p.add_argument("message", nargs="?", help="message to print")
    p.add_argument("--file", help="read message bytes from file")
    p.add_argument("--key", type=parse_hex_byte, help="optional XOR key, e.g. 0x11")
    p.add_argument("--badchars", type=parse_badchars, default=DEFAULT_BADCHARS,
                   help="comma-separated badchars, default: 00,0a,0d")
    p.add_argument("--format", choices=["hex", "c", "python", "raw", "nasm"], default="hex")
    p.add_argument("--out", help="write output to file")
    p.add_argument("--asm", help="write NASM source to file")
    p.add_argument("--strict", action="store_true", help="exit non-zero if badchars are found")
    args = p.parse_args(argv)

    if args.file:
        message = pathlib.Path(args.file).read_bytes()
    else:
        if args.message is None:
            p.error("message is required unless --file is used")
        message = args.message.encode("utf-8")
    result = build_static_shellcode(message, args.key)
    result.badchars = args.badchars

    if args.asm:
        pathlib.Path(args.asm).write_text(render_asm(message, args.key), encoding="utf-8")

    if args.format == "hex":
        output: bytes | str = fmt_hex(result.shellcode)
    elif args.format == "c":
        output = fmt_c_array(result.shellcode)
    elif args.format == "python":
        output = fmt_python(result.shellcode)
    elif args.format == "raw":
        output = result.shellcode
    elif args.format == "nasm":
        output = render_asm(message, args.key)
    else:
        raise AssertionError(args.format)

    hits = badchar_hits(result.shellcode, args.badchars)

    if args.out:
        path = pathlib.Path(args.out)
        if isinstance(output, bytes):
            path.write_bytes(output)
        else:
            path.write_text(output + "\n", encoding="utf-8")
    else:
        if isinstance(output, bytes):
            sys.stdout.buffer.write(output)
        else:
            print(output)

    print(f"\n[+] len: {len(result.shellcode)}", file=sys.stderr)
    print(f"[+] msg_len: {len(result.message)}", file=sys.stderr)
    if result.key is not None:
        print(f"[+] xor_key: 0x{result.key:02x}", file=sys.stderr)
    if hits:
        preview = ", ".join(f"offset={i}:0x{b:02x}" for i, b in hits[:16])
        more = " ..." if len(hits) > 16 else ""
        print(f"[!] badchars found: {preview}{more}", file=sys.stderr)
        return 2 if args.strict else 0
    print("[+] badchars: clean", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
