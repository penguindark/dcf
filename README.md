```markdown
# DCF - Data Cryptography File Tool

A C++17 command-line utility for creating and extracting encrypted archives using modern **ChaCha20-Poly1305 AEAD** and **SHA-256** key derivation.

## Features

- **Encrypt** files or folders into a single `.dcf` archive
- **Decrypt** `.dcf` archives back to the original folder structure
- **ChaCha20-Poly1305 AEAD** - Authenticated Encryption with Associated Data for modern, secure cryptography
- **SHA-256 Key Derivation (KDF)** - Derives unique cryptographic keys and nonces for every chunk
- **Single-file implementation** - Only the C++17 standard library is required
- **Cross-platform** - Works natively on Linux, macOS, and Windows
- **All data encrypted** - Header, paths, and content are fully encrypted
- **Cryptographic Authentication** - Poly1305 MAC tags prevent chosen-ciphertext attacks and data tampering
- **CRC32 integrity verification** - Detects accidental corruption automatically (with hardware SSE4.2 support)
- **Streaming architecture** - Processes files via an in-place 4MB push-buffer, allowing arbitrarily large files with ultra-low memory overhead
- **Custom output paths** - Specify output file with `-o` flag
- **Password support** - Interactive prompt or `-p` flag for key entry
- **Progress bar** - Real-time progress with ETA, speed, and phase status

## Options

| Flag | Description |
|------|-------------|
| `-o, --output <path>` | Custom output file path |
| `-p, --password <key>` | Encryption key (interactive if omitted) |
| `--encrypt` | Force encrypt mode |
| `--decrypt` | Force decrypt mode |
| `--no-progress` | Disable progress bar display |

## Compilation

### Linux / macOS (g++ or clang++)
```bash
g++ -std=c++17 -O3 -Wall -o dcf crypto.cpp
```
*(Optional: add `-msse4.2` to explicitly enforce hardware-accelerated CRC32 on x86_64, though the code auto-detects it in MSVC.)*

### Windows (Visual Studio C++ - Developer Command Prompt)
```cmd
cl /std:c++17 /O2 /EHsc dcf.exe crypto.cpp
```

if SSE4.2 is supported use:
```cmd
cl /EHsc /std:c++17 /O2 /arch:SSE4.2 /Fe:dcf.exe crypto.cpp
```

**Before compiling with `cl`, activate the 64-bit environment (if not using the Dev Prompt):**
```cmd
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" x64
```

## Usage

### Basic Syntax
```bash
./dcf <input> [output]           # Auto-detect mode
./dcf --encrypt <files/folder>   # Force encrypt mode
./dcf --decrypt <archive.dcf>    # Force decrypt mode
```

### Options
```bash
-o <path>   Custom output file path
-p <key>    Encryption key (or prompted if omitted)
```

### Encrypt Mode

#### Single Folder (Recursive)
```bash
./dcf myfolder/
# Creates: myfolder.dcf
```

#### Multiple Files
```bash
./dcf file1.txt file2.jpg file3.pdf
# Creates: archive.dcf (default fallback name)
```

#### Single File
```bash
./dcf document.pdf
# Creates: document.pdf.dcf
```

### Advanced Usage

#### Custom Output Path
```bash
./dcf -o /backup/myfiles.dcf myfolder/
./dcf -o encrypted.zip file1.txt file2.txt
```

#### With Password
```bash
./dcf -p "mysecretkey" file.txt          # Key from argument
./dcf -p folder/                         # Interactive password prompt
./dcf -p secret archive.dcf              # Decrypt with specific key
```

### Decrypt Mode

```bash
./dcf backup.dcf
# Extracts to the directory containing the .dcf file
# Recreates the original folder structure automatically
```

### Progress Bar

A real-time, terminal-aware progress bar is displayed by default, showing:
- Visual bar: `[#################---]`
- Progress: `45.2MB / 67.8MB (67%)`
- Speed: `125.3 MB/s`
- ETA: `00:01:23`
- Phase status: `[Building archive...]`, `[Reading header...]`, `[Verifying...]`, etc.

Disable with the `--no-progress` flag:
```bash
./dcf --no-progress file.txt    # Silent mode
```

## Encryption Algorithm

The application uses a secure, chunked **ChaCha20-Poly1305** implementation:

1. **Key Derivation (SHA-256)**: The user's password and the specific chunk index are hashed using SHA-256. This derives an independent 32-byte key and 8-byte nonce for *every* 4MB chunk of data.
2. **ChaCha20 Stream Cipher**: Data is encrypted using ChaCha20. The implementation includes word-level SIMD XOR optimizations for rapid block processing.
3. **Poly1305 Authentication (AEAD)**: A robust 26-bit limb Poly1305 algorithm calculates a 16-byte MAC (Message Authentication Code) appended to every chunk. This provides Authenticated Encryption with Associated Data, guaranteeing that ciphertexts cannot be tampered with.
4. **Streaming Serialization**: Files are streamed directly into a pre-allocated 4MB push-buffer, encrypted in-place, and immediately flushed to disk. Peak RAM overhead is practically constant regardless of total archive size.
5. **Buffered Decryption**: `BufferedStreamReader` reads chunks, verifies the Poly1305 authentication tag *before* attempting decryption (preventing chosen-ciphertext attacks), and streams plaintext back to the disk.

## Archive Format (.dcf)

All data is fully encrypted.

**Physical File Layout:**
```
+-------------------------------------------------+
| Header (20 bytes)                               |
| Encrypted directly via ChaCha20 (Chunk 0 Key)   |
| - magic: "DCF1"    (4 bytes)                    |
| - version: 4       (4 bytes, little-endian)     |
| - entryCount       (4 bytes, little-endian)     |
| - contentCrc32     (4 bytes)                    |
| - headerCrc32      (4 bytes)                    |
+-------------------------------------------------+
| Cryptographic Chunks Stream                     |
| - Chunk 0 [Encrypted Payload + 16b Poly1305 Tag]|
| - Chunk 1 [Encrypted Payload + 16b Poly1305 Tag]|
| - Chunk 2 ...                                   |
+-------------------------------------------------+
```

**Logical Layout (Inside the decrypted stream):**
```
+------------------+
| Entry 1          |
| - pathLen        | 4 bytes (little-endian uint32)
| - path           | pathLen bytes (relative path string)
| - isDirectory    | 1 byte (0=false, 1=true)
| - contentSize    | 8 bytes (little-endian uint64)
| - content        | contentSize bytes (raw file data)
+------------------+
| Entry 2 ...      |
+------------------+
```

**Version History:**
- Version 1: Original format (RC4, no CRC)
- Version 2: Added CRC32 integrity verification
- Version 3: Added parallel RC4-CTR chunked encryption
- **Version 4: Complete overhaul to ChaCha20-Poly1305 AEAD + SHA-256 KDF (Current)**

## Integrity Verification (Poly1305 & CRC32)

Integrity is strictly enforced at two levels:
1. **Cryptographic (Poly1305)**: Every 4MB chunk is individually authenticated during streaming extraction. If a single byte is flipped by an attacker or corrupted, the extraction process aborts immediately with a Poly1305 verification failure.
2. **Structural (CRC32)**: The header has its own CRC32. Additionally, a `contentCrc32` checksum validates the entirely extracted plaintext data to ensure perfect reconstruction.

## Performance

- **Large file support**: Tested with massive files (10GB+). The buffered streaming approach easily handles arbitrary sizes.
- **Constant Memory Footprint**: Peak RAM is exceptionally low (~4MB push-buffer + ~4MB read buffer) for both encryption and decryption.
- **Hardware Acceleration**: Automatically uses SSE4.2 `_mm_crc32_u64` intrinsics on supported architectures for massive CRC calculation speedups.

## Security Notes

The tool leverages **ChaCha20-Poly1305**, widely regarded as one of the most secure and performant modern software-based stream ciphers (used heavily in TLS 1.3 and WireGuard). 

*Note: While SHA-256 is used to derive distinct internal stream keys and nonces to avoid key/nonce reuse across chunks, it is a fast hash. For extreme, nation-state level threat models, pre-hashing your chosen password with a memory-hard KDF (like Argon2 or PBKDF2) before providing it to the CLI is recommended.*



## License

This project is provided under Mozilla Public License 2.0 (MPL 2.0).
```