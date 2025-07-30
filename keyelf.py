#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# author：https://github.com/8891689
import os
import sys
import hashlib
import mmap
import argparse
import subprocess
from typing import Set, List, Dict, Generator, Any

# --- Global Constants ---
MAGIC_BYTES = b'\x02\x01\x01\x04\x20' 
PRIVATE_KEY_LENGTH = 32
CHUNK_READ_SIZE = 64 * 1024 * 1024
HEX_OUTPUT_FILE = 'found_hex_keys.txt'
WIF_PREFIX_UNCOMPRESSED = b'\x80'
WIF_PREFIX_COMPRESSED = b'\x80'
WIF_SUFFIX_COMPRESSED = b'\x01'
BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

# ==============================================================================
# Core Crypto and Search Functions
# ==============================================================================

def double_sha256(data: bytes) -> bytes:
    """Performs a double SHA-256 hash."""
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()

def encode_base58_check(data_to_encode: bytes) -> str:
    """Encodes a byte string into Base58Check format."""
    checksum = double_sha256(data_to_encode)[:4]
    payload = data_to_encode + checksum
    num = int.from_bytes(payload, 'big')
    base = len(BASE58_ALPHABET)
    encoded = []
    while num > 0:
        num, remainder = divmod(num, base)
        encoded.append(BASE58_ALPHABET[remainder])
    result = "".join(reversed(encoded))
    pad_count = len(payload) - len(payload.lstrip(b'\x00'))
    return (BASE58_ALPHABET[0] * pad_count) + result

def find_keys_in_chunk(data: bytes) -> Generator[Dict[str, Any], None, None]:
    """Searches a data chunk and yields dictionaries of found key formats."""
    current_pos = 0
    while True:
        found_pos = data.find(MAGIC_BYTES, current_pos)
        if found_pos == -1: break
        key_start = found_pos + 5
        key_end = key_start + PRIVATE_KEY_LENGTH
        if key_end <= len(data):
            raw_key = data[key_start:key_end]
            payload_uncomp = WIF_PREFIX_UNCOMPRESSED + raw_key
            wif_uncomp = encode_base58_check(payload_uncomp)
            payload_comp = WIF_PREFIX_COMPRESSED + raw_key + WIF_SUFFIX_COMPRESSED
            wif_comp = encode_base58_check(payload_comp)
            yield {
                'raw_hex': raw_key.hex(),
                'wif_uncompressed': wif_uncomp,
                'wif_compressed': wif_comp,
            }
        current_pos = found_pos + 1

# ==============================================================================
# Worker & Scanning Functions
# ==============================================================================

def worker_scan_file(file_path: str):
    """
    This function is executed by a subprocess (a "worker").
    It scans a single file and prints results to stdout for the manager to capture.
    """
    try:
        if not os.path.exists(file_path) or os.path.getsize(file_path) < (len(MAGIC_BYTES) + PRIVATE_KEY_LENGTH):
            return
        with open(file_path, 'rb') as f:
            try:
                with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                    for key_dict in find_keys_in_chunk(mm):
                        print(f"{key_dict['raw_hex']}:{key_dict['wif_uncompressed']}:{key_dict['wif_compressed']}")
            except (ValueError, OSError):
                f.seek(0)
                while True:
                    chunk = f.read(CHUNK_READ_SIZE)
                    if not chunk: break
                    for key_dict in find_keys_in_chunk(chunk):
                        print(f"{key_dict['raw_hex']}:{key_dict['wif_uncompressed']}:{key_dict['wif_compressed']}")
    except Exception:
        # Errors are handled by the manager checking the worker's return code.
        # We don't want the worker to print Python exceptions to stdout.
        pass


def scan_target_with_progress(target_path: str) -> Set[str]:
    """
    Scans a single large file or block device with a progress bar.
    This version has the corrected loop logic to prevent infinite loops at the end.
    """
    print(f"[ok] Target is a single file/device. Starting direct scan...")
    found_hex_keys = set()
    try:
        with open(target_path, 'rb') as f:
            total_size = 0
            try:
                total_size = f.seek(0, os.SEEK_END)
                f.seek(0)
                print(f"[ok] Detected target size: {total_size / (1024*1024*1024):.2f} GB.")
            except (OSError, OverflowError):
                print("[!] Warning: Could not determine target size. No progress percentage will be shown.")
            
            print(f"[ok] Scanning in {CHUNK_READ_SIZE // (1024*1024)}MB chunks...")
            overlap_size = len(MAGIC_BYTES) + PRIVATE_KEY_LENGTH
            
            while True:
                # --- Correct loop structure ---
                
                # 1. Read a chunk of data
                chunk = f.read(CHUNK_READ_SIZE)
                
                # 2. Check if we've reached the end of the file
                if not chunk:
                    break # If no data was read, the scan is complete and we exit the loop

                # 3. Process the current chunk of data
                current_pos = f.tell()
                if total_size > 0:
                    progress = (current_pos / total_size) * 100
                    # Ensure progress doesn't exceed 100%
                    print(f"\r[ok] Progress: {min(progress, 100.00):.2f}%", end="", flush=True)

                for key_dict in find_keys_in_chunk(chunk):
                    if key_dict['raw_hex'] not in found_hex_keys:
                        hex_key = key_dict['raw_hex']
                        print(f"\n[+1] New private key found:")
                        print(f"     - WIF (Uncompressed): {key_dict['wif_uncompressed']}")
                        print(f"     - WIF (Compressed)  : {key_dict['wif_compressed']}")
                        try:
                            with open(HEX_OUTPUT_FILE, 'a') as f_out: f_out.write(hex_key + '\n')
                        except IOError as e:
                            print(f"[!] ERROR: Could not write to {HEX_OUTPUT_FILE}: {e}", file=sys.stderr)
                        found_hex_keys.add(key_dict['raw_hex'])

                # 4. Rewind the pointer to handle overlaps for the next read
                # Rewind only if a chunk has been fully read
                if len(chunk) == CHUNK_READ_SIZE:
                    try:
                        f.seek(f.tell() - overlap_size)
                    except OSError as e:
                        print(f"\n[!] Warning: seek operation failed: {e}. Overlapping keys might be missed.", file=sys.stderr)
                        # If seek fails, breaking out of the loop is probably the safest option.
                        break
            
            if total_size > 0: print("\r[ok] Progress: 100.00%     ") 
            print() 

    except Exception as e:
         print(f"\n[!] ERROR scanning {target_path}: {e}", file=sys.stderr)
    return found_hex_keys

# ==============================================================================
# Main Manager Program
# ==============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="A robust, high-performance Bitcoin private key scanner.",
        epilog="Example: python3 keyhunter.py ./wallets/  OR  sudo python3 keyhunter.py /dev/sdd2"
    )
    parser.add_argument("--worker-scan", help=argparse.SUPPRESS)
    parser.add_argument("path", nargs='?', default=None, help="The file, directory, or device to scan.")
    args = parser.parse_args()

    # --- Worker Process Entry Point ---
    if args.worker_scan:
        worker_scan_file(args.worker_scan)
        return

    # --- Manager Process Main Logic ---
    if not args.path:
        parser.print_help()
        print("\n[!] ERROR: A target path must be provided.", file=sys.stderr)
        return

    target_path = args.path
    all_found_hex = set()
    failed_files = []

    print("-" * 60)
    print(f"[ok] BTC Key Scanner - Analyzing Target: {target_path}")
    print(f"[ok] Hexadecimal keys will be saved to: {HEX_OUTPUT_FILE}")
    print("-" * 60)
    
    if not os.path.exists(target_path):
        print(f"[!] ERROR: Path does not exist: '{target_path}'", file=sys.stderr)
        return

    # --- LOGIC BRANCH: Directory or Single Target? ---
    if os.path.isdir(target_path):
        print("[ok] Target is a directory. Using Manager/Worker model for crash safety.")
        print("[ok] Gathering file list...")
        file_list = [os.path.join(root, filename) for root, _, files in os.walk(target_path) for filename in files if os.path.isfile(os.path.join(root, filename))]
        total_files = len(file_list)
        print(f"[ok] Found {total_files} files to scan. Starting...")
        
        terminal_width = os.get_terminal_size().columns
        for i, full_path in enumerate(file_list):
            progress = f"[ok] [{i+1}/{total_files}] Scanning: {full_path}"
            print(f"\r{progress:.{terminal_width-1}}", end="", flush=True)

            cmd = [sys.executable, __file__, "--worker-scan", full_path]
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            except subprocess.TimeoutExpired:
                failed_files.append(f"{full_path} (Timeout)")
                print(f"\r{' ' * (terminal_width-1)}\r", end="")
                print(f"[!] WARNING: Worker timed out on file, skipped: {full_path}")
                continue

            if result.returncode != 0:
                failed_files.append(f"{full_path} (Crashed, code: {result.returncode})")
                print(f"\r{' ' * (terminal_width-1)}\r", end="")
                print(f"[!] WARNING: Worker crashed on file, skipped: {full_path}")
            
            if result.stdout:
                for line in result.stdout.strip().split('\n'):
                    if not line: continue
                    parts = line.split(':')
                    if len(parts) == 3:
                        hex_key, wif_uncomp, wif_comp = parts
                        if hex_key not in all_found_hex:
                            print(f"\r{' ' * (terminal_width-1)}\r", end="")
                            print(f"[+1] New private key found (Source: {full_path})")
                            print(f"   - WIF (Uncompressed): {wif_uncomp}")
                            print(f"   - WIF (Compressed)  : {wif_comp}")
                            try:
                                with open(HEX_OUTPUT_FILE, 'a') as f: f.write(hex_key + '\n')
                            except IOError as e:
                                print(f"[!] ERROR: Could not write to {HEX_OUTPUT_FILE}: {e}", file=sys.stderr)
                            all_found_hex.add(hex_key)
        
        print(f"\r{' ' * (terminal_width-1)}\r", end="")

    else: # Target is a single file or a block device
        all_found_hex = scan_target_with_progress(target_path)

    # --- Final Report ---
    print("\n" + "-" * 60)
    print("[ok] Scan Complete.")
    if all_found_hex:
        print(f"[ok] Summary: Found {len(all_found_hex)} unique private keys.")
        print(f"[ok] All hexadecimal private keys have been saved to {HEX_OUTPUT_FILE}.")
    if failed_files:
        print(f"\n[!] WARNING: {len(failed_files)} files caused issues during the scan:")
        for f in failed_files:
            print(f"    - {f}")
    if not all_found_hex and not failed_files:
        print("[no] Summary: No private keys matching the criteria were found.")
    print("-" * 60)

if __name__ == "__main__":
    main()
