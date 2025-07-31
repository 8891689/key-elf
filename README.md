keyelf This Python script is specifically designed for recovering Bitcoin private keys from corrupted or accidentally deleted data sources.
It doesn't rely on a complete file structure, but instead locates private keys by directly scanning the raw binary data.

1. Core Principle:
The tool locates potential private keys by searching for a specific Bitcoin private key signature (ASN.1 structure prefix) within the data stream. 
Once found, it extracts the subsequent 32-byte raw key and automatically converts it to both the standard WIF (Wallet Import Format) compressed and uncompressed formats for direct import into a wallet.

2. Key Features:
Multi-mode Scanning:
Supports scanning single files (such as wallet.dat), entire file directories, and block devices (such as hard drive partitions /dev/sdb or disk images).

3. Highly Reliable Architecture: 
Utilizes a "manager-worker" model when scanning directories.
Each file is handled by a separate child process. Even if a file causes the scan to crash, the main process continues running, ensuring the integrity of the scan.

4. High-Performance I/O: 
Prefers using mmap for file memory mapping to improve scanning speed, and automatically falls back to traditional block-based reading.
For large file scans, a built-in progress bar and boundary overlap detection are included to prevent missed files.

5. Ready-to-use output:
Displays found WIF formatted private keys directly in the console and backs up all raw hexadecimal private keys to found_hex_keys.txt.


# To run the script, simply use the following command (replace [target path] with the file, directory, or device you want to scan):

1. Scan a folder
```
python3 keyelf.py /path/to/your/wallets_folder/
```
2. Scan a single file
```
python3 keyelf.py wallet.dat
```
3. Scan an entire hard drive partition (usually requires administrator privileges)
```
sudo python3 keyelf.py /dev/sdb1
```

# For example, a test to find the BTC private key in a deleted wallet file from the hard drive.
```
sudo python3 keyelf.py /dev/sde1
------------------------------------------------------------
[ok] BTC Key Scanner - Analyzing Target: /dev/sde1
[ok] Hexadecimal keys will be saved to: found_hex_keys.txt
------------------------------------------------------------
[ok] Target is a single file/device. Starting direct scan...
[ok] Detected target size: 238.47 GB.
[ok] Scanning in 64MB chunks...
[ok] Progress: 17.93%
[+1] New private key found:
     - WIF (Uncompressed): 5JgcxewbUkZcmy3KfM4SesCtXJ3iyTrbhY8rsfcUPqzES9LEg4b
     - WIF (Compressed)  : L13sieTyBVGxuUMFNFYCE8bUQiF2GDXv9vRh8dRZuqDcHgsmgf6D

[+1] New private key found:
     - WIF (Uncompressed): 5JFYU7mdL1ByBbysgYkaujckrUKRMGb5fGWafLrkerov3D5CyzD
     - WIF (Compressed)  : Ky9BtgsyLsqQyoQ2hZ9Nfm6pZMaJUToRZuTZaEebg6r56eW8igyJ

[+1] New private key found:
     - WIF (Uncompressed): 5J58DspFV9VYWozpG4EwCHyew782RvbPsEZnKruaGpNkZJmdUTL
     - WIF (Compressed)  : KxMCsqHYwEUz6aSBbTJWCqw4Rp21K1Yovish4FH3rp71FN8yyfv3

[+1] New private key found:
     - WIF (Uncompressed): 5JQGKqJCsvPZze6b9vRLDrRHAm2dBqaaV7cE3JAmGH8wb7yQCxB
     - WIF (Compressed)  : Kyoge8AwRkecdQjfkNnPqj8AN5LAiqRCo6AUZ8n6NSE3wZUttP6e
[ok] Progress: 100.00%     


------------------------------------------------------------
[ok] Scan Complete.
[ok] Summary: Found 4 unique private keys.
[ok] All hexadecimal private keys have been saved to found_hex_keys.txt.
------------------------------------------------------------
```
# For example, testing with a shared wallet.
```
python3 keyelf.py /home/Many-wallets/LostWallets-main
------------------------------------------------------------
[ok] BTC Key Scanner - Analyzing Target: /home/Many-wallets/LostWallets-main
[ok] Hexadecimal keys will be saved to: found_hex_keys.txt
------------------------------------------------------------
[ok] Target is a directory. Using Manager/Worker model for crash safety.
[ok] Gathering file list...
[ok] Found 33667 files to scan. Starting...
[+1] New private key found (Source: /home/Many-wallets/LostWallets-main/2/25.75-BTC.dat)                                                  
   - WIF (Uncompressed): 5JcKu5rkEQEH5VdKvynSb7ASQHixu83q2Y8FRqFXykQWKBPWax7
   - WIF (Compressed)  : KzivQtSZp9XbxqMLZFdZwYCf7npDj47UynNzgby9jUakPB6KNKcC
[+1] New private key found (Source: /home/hooj/LostWallets-main/2/25.75-BTC.dat)                                                  
   - WIF (Uncompressed): 5HwMcPBb6v2AoUGAzsPrWGDhZiSzYj8vPBxmfGYLDoxEj7qmKrc
   - WIF (Compressed)  : KwkuyAujX72AG7Ky8RRsWAB43Pwj12yxcwPA7ubHqYEoadY73Scd

*
*
*
*
*
*
[+1] New private key found (Source: /home/hooj/LostWallets-main/1/0.00000547-BTC.dat)                                             
   - WIF (Uncompressed): 5JdzUghgyXHP3sskKDkxzhbXxUQSLCLh2QxBDBEH6DvXEQ1jchs
   - WIF (Compressed)  : KzrGhCEbSUfJKhYzBRK49gBRdqxSoj3ufEiY4k9c243ERuHmN5b1
[+1] New private key found (Source: /home/hooj/LostWallets-main/1/0.00000547-BTC.dat)                                             
   - WIF (Uncompressed): 5KYNdKe8wnN6RjEam7HrYojU5ynvjYkaeaWHEgbDfSt46Xm6R5D
   - WIF (Compressed)  : L4qUTKGv4oE6x9Qx1gmPhPGSYyfiAo9MWrtEfPk2thELeyVbSXdT
[+1] New private key found (Source: /home/hooj/LostWallets-main/1/0.00000547-BTC.dat)                                             
   - WIF (Uncompressed): 5JaX6nQKkqUS6V3bYCNngmk437H77mBPJ1LrRPJby6reeapKyFw
   - WIF (Compressed)  : KzawrXPwnUx5mCnTShDAeYV2QJi5zqzqQ4Wd8dShLcr9AZ5sSRpr
                                                                                                                                  
------------------------------------------------------------
[ok] Scan Complete.
[ok] Summary: Found 1832 unique private keys.
[ok] All hexadecimal private keys have been saved to found_hex_keys.txt.

```
# Output file data structure:
```
found_hex_keys.txt

688a129f03a3bc1e4003c69e7f59d70344cc7bc720cca63eff722e7e06e97fd9
100d566ca174eb737a290345e6f0bb4f41b1bcb088d7e8426834c1f205a171f1
*
*
*
*
*
71e9dd980f97caf092093463826419a62e2c5c98e9d745eb820e2689cd70a202
103f368dd5b6f376c61c650a891df361f75e5263995d6979b0b9aaa7c267b9bc
```


# Sponsorship
If this project was helpful to you, please buy me a coffee. Your support is greatly appreciated. Thank you!
```
BTC: bc1qt3nh2e6gjsfkfacnkglt5uqghzvlrr6jahyj2k
ETH: 0xD6503e5994bF46052338a9286Bc43bC1c3811Fa1
DOGE: DTszb9cPALbG9ESNJMFJt4ECqWGRCgucky
TRX: TAHUmjyzg7B3Nndv264zWYUhQ9HUmX4Xu4
```

# 📜 Disclaimer
Reminder: Do not enter the real private key on the connected device!

This tool is only used for learning, analysis, vulnerability repair, software testing BUG and other research. 
Please use it with understanding of the relevant risks. Cracking other people's private keys is unethical and will be subject to legal sanctions. 
Please abide by local laws and regulations. The developer does not assume any responsibility for economic losses or legal liabilities caused by the use of this tool.
