// ============================================================================
// DCF - Data Cryptography File Tool
// C++17 CLI utility for encrypted archive creation and extraction
// 
// Usage:
//   Compile: g++ -std=c++17 -O3 -Wall -o dcf dcf.cpp
//            (On Windows/MSVC: cl /std:c++17 /O2 /EHsc dcf.cpp)
//   Encrypt: ./dcf <file(s) or folder> [-o output.dcf] [-p key]
//   Decrypt: ./dcf <archive.dcf> [-p key]
// ============================================================================

#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <filesystem>
#include <cstdint>
#include <cstring>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <mutex>
#include <future>
#include <thread>
#include <cstddef>
#include <memory>

#ifdef _MSC_VER
    #if defined(_M_X64) || defined(_M_AMD64)
        #define __SSE4_2__
    #endif
#endif

#ifdef __SSE4_2__
#include <nmmintrin.h>
#endif

#define NOMINMAX
#ifdef _WIN32
    #include <io.h>
    #include <conio.h>
    #include <windows.h>
#else
    #include <unistd.h>
    #include <termios.h>
    #include <sys/ioctl.h>
#endif

namespace fs = std::filesystem;

// ============================================================================
// GLOBAL CONFIGURATION
// ============================================================================
constexpr const char* DEFAULT_KEY = "mysecretkey";  // Default encryption key
constexpr const char* MAGIC = "DCF1";               // Archive magic bytes
constexpr uint32_t VERSION = 4;                     // Archive version

// ============================================================================
// SHA-256 IMPLEMENTATION (For Secure Key Derivation)
// ============================================================================
namespace sha256 {
    constexpr uint32_t K[64] = {
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
    };

    inline uint32_t rotr(uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); }

    void hash(const uint8_t* data, size_t len, uint8_t out[32]) {
        uint32_t state[8] = {
            0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
            0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
        };
        uint64_t bitlen = static_cast<uint64_t>(len) * 8;
        std::vector<uint8_t> padded(data, data + len);
        padded.push_back(0x80);
        while ((padded.size() % 64) != 56) padded.push_back(0x00);
        for (int i = 7; i >= 0; --i) padded.push_back(static_cast<uint8_t>((bitlen >> (i * 8)) & 0xFF));

        for (size_t offset = 0; offset < padded.size(); offset += 64) {
            uint32_t w[64] = {0};
            for (size_t i = 0; i < 16; ++i) {
                w[i] = ((uint32_t)padded[offset+i*4] << 24) | ((uint32_t)padded[offset+i*4+1] << 16) |
                       ((uint32_t)padded[offset+i*4+2] << 8) | ((uint32_t)padded[offset+i*4+3]);
            }
            for (size_t i = 16; i < 64; ++i) {
                uint32_t s0 = rotr(w[i-15], 7) ^ rotr(w[i-15], 18) ^ (w[i-15] >> 3);
                uint32_t s1 = rotr(w[i-2], 17) ^ rotr(w[i-2], 19) ^ (w[i-2] >> 10);
                w[i] = w[i-16] + s0 + w[i-7] + s1;
            }
            uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
            uint32_t e = state[4], f = state[5], g = state[6], h = state[7];

            for (size_t i = 0; i < 64; ++i) {
                uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
                uint32_t ch = (e & f) ^ (~e & g);
                uint32_t temp1 = h + S1 + ch + K[i] + w[i];
                uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
                uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
                uint32_t temp2 = S0 + maj;

                h = g; g = f; f = e; e = d + temp1;
                d = c; c = b; b = a; a = temp1 + temp2;
            }
            state[0] += a; state[1] += b; state[2] += c; state[3] += d;
            state[4] += e; state[5] += f; state[6] += g; state[7] += h;
        }
        for (size_t i = 0; i < 8; ++i) {
            out[i*4]   = (state[i] >> 24) & 0xFF; out[i*4+1] = (state[i] >> 16) & 0xFF;
            out[i*4+2] = (state[i] >> 8) & 0xFF;  out[i*4+3] = state[i] & 0xFF;
        }
    }
}

// ============================================================================
// CRC32 IMPLEMENTATION (Integrity Checksum)
// ============================================================================

class CRC32 {
public:
    CRC32() : m_crc(0xFFFFFFFF) {}
    
    void update(const void* data, size_t length) {
        const uint8_t* bytes = static_cast<const uint8_t*>(data);
#ifdef __SSE4_2__
        size_t i = 0;
        for (; i + 8 <= length; i += 8) {
            m_crc = static_cast<uint32_t>(_mm_crc32_u64(m_crc, *reinterpret_cast<const uint64_t*>(bytes + i)));
        }
        for (; i < length; i++) {
            m_crc = static_cast<uint32_t>(_mm_crc32_u8(m_crc, bytes[i]));
        }
#else
        for (size_t i = 0; i < length; i++) {
            m_crc = table[(m_crc ^ bytes[i]) & 0xFF] ^ (m_crc >> 8);
        }
#endif
    }
    
    uint32_t finalize() { return m_crc ^ 0xFFFFFFFF; }
    void reset() { m_crc = 0xFFFFFFFF; }
    static uint32_t calculate(const void* data, size_t length) { CRC32 crc; crc.update(data, length); return crc.finalize(); }
    
private:
    uint32_t m_crc;
    static const uint32_t table[256];
};

const uint32_t CRC32::table[256] = {
    0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA, 0x076DC419, 0x706AF48F,
    0xE963A535, 0x9E6495A3, 0x0EDB8832, 0x79DCB8A4, 0xE0D5E91E, 0x97D2D988,
    0x09B64C2B, 0x7EB17CBD, 0xE7B82D07, 0x90BF1D91, 0x1DB71064, 0x6AB020F2,
    0xF3B97148, 0x84BE41DE, 0x1ADAD47D, 0x6DDDE4EB, 0xF4D4B551, 0x83D385C7,
    0x136C9856, 0x646BA8C0, 0xFD62F97A, 0x8A65C9EC, 0x14015C4F, 0x63066CD9,
    0xFA0F3D63, 0x8D080DF5, 0x3B6E20C8, 0x4C69105E, 0xD56041E4, 0xA2677172,
    0x3C03E4D1, 0x4B04D447, 0xD20D85FD, 0xA50AB56B, 0x35B5A8FA, 0x42B2986C,
    0xDBBBC9D6, 0xACBCF940, 0x32D86CE3, 0x45DF5C75, 0xDCD60DCF, 0xABD13D59,
    0x26D930AC, 0x51DE003A, 0xC8D75180, 0xBFD06116, 0x21B4F4B5, 0x56B3C423,
    0xCFBA9599, 0xB8BDA50F, 0x2802B89E, 0x5F058808, 0xC60CD9B2, 0xB10BE924,
    0x2F6F7C87, 0x58684C11, 0xC1611DAB, 0xB6662D3D, 0x76DC4190, 0x01DB7106,
    0x98D220BC, 0xEFD5102A, 0x71B18589, 0x06B6B51F, 0x9FBFE4A5, 0xE8B8D433,
    0x7807C9A2, 0x0F00F934, 0x9609A88E, 0xE10E9818, 0x7F6A0DBB, 0x086D3D2D,
    0x91646C97, 0xE6635C01, 0x6B6B51F4, 0x1C6C6162, 0x856530D8, 0xF262004E,
    0x6C0695ED, 0x1B01A57B, 0x8208F4C1, 0xF50FC457, 0x65B0D9C6, 0x12B7E950,
    0x8BBEB8EA, 0xFCB9887C, 0x62DD1DDF, 0x15DA2D49, 0x8CD37CF3, 0xFBD44C65,
    0x4DB26158, 0x3AB551CE, 0xA3BC0074, 0xD4BB30E2, 0x4ADFA541, 0x3DD895D7,
    0xA4D1C46D, 0xD3D6F4FB, 0x4369E96A, 0x346ED9FC, 0xAD678846, 0xDA60B8D0,
    0x44042D73, 0x33031DE5, 0xAA0A4C5F, 0xDD0D7CC9, 0x5005713C, 0x270241AA,
    0xBE0B1010, 0xC90C2086, 0x5768B525, 0x206F85B3, 0xB966D409, 0xCE61E49F,
    0x5EDEF90E, 0x29D9C998, 0xB0D09822, 0xC7D7A8B4, 0x59B33D17, 0x2EB40D81,
    0xB7BD5C3B, 0xC0BA6CAD, 0xEDB88320, 0x9ABFB3B6, 0x03B6E20C, 0x74B1D29A,
    0xEAD54739, 0x9DD277AF, 0x04DB2615, 0x73DC1683, 0xE3630B12, 0x94643B84,
    0x0D6D6A3E, 0x7A6A5AA8, 0xE40ECF0B, 0x9309FF9D, 0x0A00AE27, 0x7D079EB1,
    0xF00F9344, 0x8708A3D2, 0x1E01F268, 0x6906C2FE, 0xF762575D, 0x806567CB,
    0x196C3671, 0x6E6B06E7, 0xFED41B76, 0x89D32BE0, 0x10DA7A5A, 0x67DD4ACC,
    0xF9B9DF6F, 0x8EBEEFF9, 0x17B7BE43, 0x60B08ED5, 0xD6D6A3E8, 0xA1D1937E,
    0x38D8C2C4, 0x4FDFF252, 0xD1BB67F1, 0xA6BC5767, 0x3FB506DD, 0x48B2364B,
    0xD80D2BDA, 0xAF0A1B4C, 0x36034AF6, 0x41047A60, 0xDF60EFC3, 0xA867DF55,
    0x316E8EEF, 0x4669BE79, 0xCB61B38C, 0xBC66831A, 0x256FD2A0, 0x5268E236,
    0xCC0C7795, 0xBB0B4703, 0x220216B9, 0x5505262F, 0xC5BA3BBE, 0xB2BD0B28,
    0x2BB45A92, 0x5CB36A04, 0xC2D7FFA7, 0xB5D0CF31, 0x2CD99E8B, 0x5BDEAE1D,
    0x9B64C2B0, 0xEC63F226, 0x756AA39C, 0x026D930A, 0x9C0906A9, 0xEB0E363F,
    0x72076785, 0x05005713, 0x95BF4A82, 0xE2B87A14, 0x7BB12BAE, 0x0CB61B38,
    0x92D28E9B, 0xE5D5BE0D, 0x7CDCEFB7, 0x0BDBDF21, 0x86D3D2D4, 0xF1D4E242,
    0x68DDB3F8, 0x1FDA836E, 0x81BE16CD, 0xF6B9265B, 0x6FB077E1, 0x18B74777,
    0x88085AE6, 0xFF0F6A70, 0x66063BCA, 0x11010B5C, 0x8F659EFF, 0xF862AE69,
    0x616BFFD3, 0x166CCF45, 0xA00AE278, 0xD70DD2EE, 0x4E048354, 0x3903B3C2,
    0xA7672661, 0xD06016F7, 0x4969474D, 0x3E6E77DB, 0xAED16A4A, 0xD9D65ADC,
    0x40DF0B66, 0x37D83BF0, 0xA9BCAE53, 0xDEBB9EC5, 0x47B2CF7F, 0x30B5FFE9,
    0xBDBDF21C, 0xCABAC28A, 0x53B39330, 0x24B4A3A6, 0xBAD03605, 0xCDD70693,
    0x54DE5729, 0x23D967BF, 0xB3667A2E, 0xC4614AB8, 0x5D681B02, 0x2A6F2B94,
    0xB40BBE37, 0xC30C8EA1, 0x5A05DF1B, 0x2D02EF8D
};

// ============================================================================
// PROGRESS BAR UTILITY
// ============================================================================

class ProgressBar {
public:
    ProgressBar(const std::string& label, size_t totalBytes)
        : m_label(label), m_total(totalBytes), m_current(0), m_finished(false) {
        m_startTime = std::chrono::steady_clock::now();
        m_enabled = isTerminal();
        m_lastUpdate = 0;
    }
    
    void update(size_t current, const std::string& status = "") {
        m_current = current;
        if (!status.empty()) m_status = status;
        
        auto now = std::chrono::steady_clock::now();
        double elapsed = std::chrono::duration<double>(now - m_startTime).count();
        if (elapsed - m_lastUpdate < 0.1 && m_current < m_total) return; // Throttle rendering
        m_lastUpdate = elapsed;
        
        if (!m_enabled || m_finished) return;
        render(elapsed);
    }
    
    void setTotal(size_t newTotal) { m_total = newTotal; }
    void setStatus(const std::string& status) { m_status = status; update(m_current); }
    
    void finish() {
        m_finished = true;
        if (!m_enabled) return;
        auto now = std::chrono::steady_clock::now();
        render(std::chrono::duration<double>(now - m_startTime).count());
        std::cout << std::endl; // Safely move to the next line without overwriting the completed bar
    }
    
private:
    static int getTerminalWidth() {
#ifdef _WIN32
        CONSOLE_SCREEN_BUFFER_INFO csbi;
        if (GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &csbi)) {
            return csbi.srWindow.Right - csbi.srWindow.Left + 1;
        }
        return 80; // Fallback
#else
        struct winsize w;
        if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &w) != -1) {
            return w.ws_col;
        }
        return 80; // Fallback
#endif
    }

    std::string formatTime(double seconds) {
        int s = static_cast<int>(seconds);
        int h = s / 3600;
        int m = (s % 3600) / 60;
        s = s % 60;
        std::ostringstream oss;
        oss << std::setfill('0');
        if (h > 0) {
            oss << std::setw(2) << h << ":";
        }
        oss << std::setw(2) << m << ":" << std::setw(2) << s;
        return oss.str();
    }

    void render(double elapsed) {
        int termWidth = getTerminalWidth();
        if (termWidth < 30) termWidth = 80; // Fallback for safety

        int width = 20; // Compressed bar graphic to fit more text
        double progress = m_total > 0 ? static_cast<double>(m_current) / m_total : 0.0;
        if (progress > 1.0) progress = 1.0;
        
        int filled = static_cast<int>(progress * width);
        std::string bar = "[" + std::string(filled, '#') + std::string(width - filled, '-') + "]";
        
        std::string speed = formatBytes(static_cast<size_t>(elapsed > 0 ? static_cast<double>(m_current) / elapsed : 0)) + "/s";
        std::string pctStr = std::to_string(static_cast<int>(progress * 100)) + "%";
        
        std::string timeElapsed = formatTime(elapsed);
        std::string timeETA = "--:--";
        
        if (m_current > 0 && m_total > 0 && m_current < m_total && elapsed > 0) {
            double currentSpeed = static_cast<double>(m_current) / elapsed;
            double remainingBytes = static_cast<double>(m_total - m_current);
            double etaSeconds = remainingBytes / currentSpeed;
            timeETA = formatTime(etaSeconds);
        } else if (m_current >= m_total && m_total > 0) {
            timeETA = "00:00";
        }
        
        std::ostringstream oss;
        oss << m_label << " " << bar << " " << formatBytes(m_current) << "/" 
            << formatBytes(m_total) << " " << pctStr << " " << speed
            << " ETA: " << timeETA;
        if (!m_status.empty()) oss << " [" << m_status << "]";
        
        std::string outStr = oss.str();

        // **CRITICAL FIX**: Truncate output text strictly before terminal width
        // If the text length is >= terminal width, the console will implicitly wrap it 
        // to a new line, thus resulting in constant downward scrolling!
        if (outStr.length() >= static_cast<size_t>(termWidth)) {
            outStr = outStr.substr(0, termWidth - 1);
        }
        
        // The \r moves the cursor back to the line start and \033[K securely clears any trailing characters
        std::cout << "\r\033[K" << outStr << std::flush;
    }
    
    std::string formatBytes(size_t bytes) {
        double b = static_cast<double>(bytes);
        std::ostringstream oss;
        oss << std::fixed << std::setprecision(1);
        
        if (b >= 1073741824.0) { oss << (b / 1073741824.0) << "GB"; return oss.str(); }
        if (b >= 1048576.0)    { oss << (b / 1048576.0) << "MB";    return oss.str(); }
        if (b >= 1024.0)       { oss << (b / 1024.0) << "KB";       return oss.str(); }
        
        return std::to_string(bytes) + "B";
    }
    
    static bool isTerminal() {
#ifdef _WIN32
        return _isatty(_fileno(stdout)) != 0;
#else
        return isatty(fileno(stdout)) != 0;
#endif
    }
    
    std::string m_label;
    size_t m_total, m_current;
    std::string m_status;
    bool m_finished, m_enabled;
    std::chrono::steady_clock::time_point m_startTime;
    double m_lastUpdate;
};

// ============================================================================
// CHACHA20-POLY1305 AEAD CHUNKED ENCRYPTION
// ============================================================================

constexpr size_t CHUNK_SIZE = 4 * 1024 * 1024;          // 4MB data chunks
constexpr size_t TAG_SIZE = 16;                           // Poly1305 tag size

static void chachaQuarterRound(uint32_t* s, size_t a, size_t b, size_t c, size_t d) {
    s[a] = (s[a] + s[b]); s[d] ^= s[a]; s[d] = ((s[d] << 16) | (s[d] >> 16));
    s[c] = (s[c] + s[d]); s[b] ^= s[c]; s[b] = ((s[b] << 12) | (s[b] >> 20));
    s[a] = (s[a] + s[b]); s[d] ^= s[a]; s[d] = ((s[d] << 8) | (s[d] >> 24));
    s[c] = (s[c] + s[d]); s[b] ^= s[c]; s[b] = ((s[b] << 7) | (s[b] >> 25));
}

static void chachaBlock(const uint32_t* input, uint32_t* output) {
    uint32_t x[16];
    std::memcpy(x, input, sizeof(x));
    for (int round = 0; round < 20; round += 2) {
        chachaQuarterRound(x, 0, 4, 8, 12); chachaQuarterRound(x, 1, 5, 9, 13);
        chachaQuarterRound(x, 2, 6, 10, 14); chachaQuarterRound(x, 3, 7, 11, 15);
        chachaQuarterRound(x, 0, 5, 10, 15); chachaQuarterRound(x, 1, 6, 11, 12);
        chachaQuarterRound(x, 2, 7, 8, 13); chachaQuarterRound(x, 3, 4, 9, 14);
    }
    for (size_t i = 0; i < 16; i++) output[i] = x[i] + input[i];
}

static void chachaEncrypt(const uint8_t* in, size_t len, const uint8_t* key,
                          uint32_t counter, const uint64_t nonce, uint8_t* out) {
    uint32_t state[16] = { 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574 };
    for (int i = 0; i < 8; i++) {
        state[4 + i] = 0;
        for (int j = 0; j < 4; j++) state[4 + i] |= static_cast<uint32_t>(key[i * 4 + j]) << (j * 8);
    }
    state[12] = counter;
    state[13] = static_cast<uint32_t>(nonce);
    state[14] = static_cast<uint32_t>(nonce >> 32);
    state[15] = 0;
    
    size_t offset = 0;
    uint32_t block[16], keystream[16];
    
    while (offset < len) {
        std::memcpy(block, state, sizeof(block));
        chachaBlock(block, keystream);
        
        size_t remaining = len - offset;
        size_t toProcess = std::min(remaining, size_t(64));
        size_t words = toProcess / 4;

        // SIMD WORD-LEVEL XOR OPTIMIZATION
        for (size_t i = 0; i < words; i++) {
            uint32_t in_word;
            std::memcpy(&in_word, in + offset + i * 4, 4);
            uint32_t out_word = in_word ^ keystream[i];
            std::memcpy(out + offset + i * 4, &out_word, 4);
        }
        for (size_t i = words * 4; i < toProcess; i++) {
            out[offset + i] = in[offset + i] ^ static_cast<uint8_t>(keystream[i / 4] >> ((i % 4) * 8));
        }
        
        offset += toProcess;
        state[12]++;
    }
}

static void chachaDecrypt(const uint8_t* in, size_t len, const uint8_t* key, uint32_t counter, uint64_t nonce, uint8_t* out) {
    chachaEncrypt(in, len, key, counter, nonce, out); // Symmetric
}

/** 
 * Fixed: Robust 26-bit limb Poly1305 Implementation
 * Guaranteed to operate cleanly within 64-bit boundaries (No C4293 shift overflows!)
 */
static void poly1305Mac(const uint8_t* msg, size_t msgLen, const uint8_t* key, uint8_t* tag) {
    // 1. Setup Clamped 'r' Key in 26-bit limbs
    uint32_t t0 = (uint32_t)key[0] | ((uint32_t)key[1]<<8) | ((uint32_t)key[2]<<16) | ((uint32_t)key[3]<<24);
    uint32_t t1 = (uint32_t)key[4] | ((uint32_t)key[5]<<8) | ((uint32_t)key[6]<<16) | ((uint32_t)key[7]<<24);
    uint32_t t2 = (uint32_t)key[8] | ((uint32_t)key[9]<<8) | ((uint32_t)key[10]<<16) | ((uint32_t)key[11]<<24);
    uint32_t t3 = (uint32_t)key[12] | ((uint32_t)key[13]<<8) | ((uint32_t)key[14]<<16) | ((uint32_t)key[15]<<24);

    uint64_t r0 = t0 & 0x3FFFFFF;
    uint64_t r1 = ((t0 >> 26) | (t1 << 6)) & 0x3FFFF03;
    uint64_t r2 = ((t1 >> 20) | (t2 << 12)) & 0x3FFC0FF;
    uint64_t r3 = ((t2 >> 14) | (t3 << 18)) & 0x3F03FFF;
    uint64_t r4 = (t3 >> 8) & 0x00FFFFF;

    uint64_t h0 = 0, h1 = 0, h2 = 0, h3 = 0, h4 = 0;

    // 2. Process Blocks
    for (size_t pos = 0; pos < msgLen; pos += 16) {
        size_t n = std::min(size_t(16), msgLen - pos);
        uint8_t block[17] = {0};
        std::memcpy(block, msg + pos, n);
        block[n] = 1; // High bit padding

        // Convert block to 26-bit limbs safely
        uint64_t c0 = ((uint64_t)block[0] | ((uint64_t)block[1]<<8) | ((uint64_t)block[2]<<16) | ((uint64_t)block[3]<<24)) & 0x3FFFFFF;
        uint64_t c1 = (((uint64_t)block[3]>>2) | ((uint64_t)block[4]<<6) | ((uint64_t)block[5]<<14) | ((uint64_t)block[6]<<22)) & 0x3FFFFFF;
        uint64_t c2 = (((uint64_t)block[6]>>4) | ((uint64_t)block[7]<<4) | ((uint64_t)block[8]<<12) | ((uint64_t)block[9]<<20)) & 0x3FFFFFF;
        uint64_t c3 = (((uint64_t)block[9]>>6) | ((uint64_t)block[10]<<2) | ((uint64_t)block[11]<<10) | ((uint64_t)block[12]<<18)) & 0x3FFFFFF;
        uint64_t c4 = ((uint64_t)block[13] | ((uint64_t)block[14]<<8) | ((uint64_t)block[15]<<16) | ((uint64_t)block[16]<<24));

        h0 += c0; h1 += c1; h2 += c2; h3 += c3; h4 += c4;

        // Multiply step (products remain fully within 64-bit boundaries)
        uint64_t d0 = h0*r0 + h1*r4*5 + h2*r3*5 + h3*r2*5 + h4*r1*5;
        uint64_t d1 = h0*r1 + h1*r0   + h2*r4*5 + h3*r3*5 + h4*r2*5;
        uint64_t d2 = h0*r2 + h1*r1   + h2*r0   + h3*r4*5 + h4*r3*5;
        uint64_t d3 = h0*r3 + h1*r2   + h2*r1   + h3*r0   + h4*r4*5;
        uint64_t d4 = h0*r4 + h1*r3   + h2*r2   + h3*r1   + h4*r0;

        // Partial reduction step
        uint64_t c;
        c = d0 >> 26; h0 = d0 & 0x3FFFFFF; d1 += c;
        c = d1 >> 26; h1 = d1 & 0x3FFFFFF; d2 += c;
        c = d2 >> 26; h2 = d2 & 0x3FFFFFF; d3 += c;
        c = d3 >> 26; h3 = d3 & 0x3FFFFFF; d4 += c;
        c = d4 >> 26; h4 = d4 & 0x3FFFFFF; h0 += c * 5;
        c = h0 >> 26; h0 = h0 & 0x3FFFFFF; h1 += c;
    }

    // 3. Final Full Reduction
    uint64_t c;
    c = h1 >> 26; h1 &= 0x3FFFFFF; h2 += c;
    c = h2 >> 26; h2 &= 0x3FFFFFF; h3 += c;
    c = h3 >> 26; h3 &= 0x3FFFFFF; h4 += c;
    c = h4 >> 26; h4 &= 0x3FFFFFF; h0 += c * 5;
    c = h0 >> 26; h0 &= 0x3FFFFFF; h1 += c;

    // Check if we need to subtract 2^130-5
    uint64_t g0 = h0 + 5; c = g0 >> 26; g0 &= 0x3FFFFFF;
    uint64_t g1 = h1 + c; c = g1 >> 26; g1 &= 0x3FFFFFF;
    uint64_t g2 = h2 + c; c = g2 >> 26; g2 &= 0x3FFFFFF;
    uint64_t g3 = h3 + c; c = g3 >> 26; g3 &= 0x3FFFFFF;
    uint64_t g4 = h4 + c - (1ULL << 26);

    // If subtraction didn't underflow, commit it
    if ((g4 & (1ULL << 63)) == 0) {
        h0 = g0; h1 = g1; h2 = g2; h3 = g3; h4 = g4;
    }

    // 4. Transform to 128-bit MAC
    uint64_t mac0 = h0 | (h1 << 26) | (h2 << 52);
    uint64_t mac1 = (h2 >> 12) | (h3 << 14) | (h4 << 40);

    // Setup 's' Key addition
    uint64_t s0 = 0, s1 = 0;
    for (int i = 0; i < 8; i++) {
        s0 |= ((uint64_t)key[16+i]) << (i*8);
        s1 |= ((uint64_t)key[24+i]) << (i*8);
    }

    // Add and populate output
    uint64_t out0 = mac0 + s0;
    uint64_t out1 = mac1 + s1 + (out0 < mac0);

    for (int i = 0; i < 8; i++) {
        tag[i] = (out0 >> (i*8)) & 0xFF;
        tag[i+8] = (out1 >> (i*8)) & 0xFF;
    }
}

/** SECURE KDF: Derives 32-byte key & 8-byte nonce using SHA-256 for independent chunk streams */
static void deriveKeyAndNonce(const std::string& key, size_t chunkIndex, uint8_t* outKey, uint64_t* outNonce) {
    std::vector<uint8_t> input(key.begin(), key.end());
    for(int i=0; i<8; i++) input.push_back((static_cast<uint64_t>(chunkIndex) >> (i*8)) & 0xFF);
    
    input.push_back(0); // Suffix '0' for Key
    sha256::hash(input.data(), input.size(), outKey);
    
    input.back() = 1; // Suffix '1' for Nonce
    uint8_t nonceHash[32];
    sha256::hash(input.data(), input.size(), nonceHash);
    std::memcpy(outNonce, nonceHash, sizeof(uint64_t));
}

static bool chachaEncryptChunk(const uint8_t* in, size_t len, const std::string& key, size_t chunkIndex, uint8_t* out) {
    uint8_t chunkKey[32]; uint64_t nonce;
    deriveKeyAndNonce(key, chunkIndex, chunkKey, &nonce);
    
    uint32_t polyState[16] = { 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574 };
    for (int i = 0; i < 8; i++) {
        polyState[4 + i] = 0;
        for (int j = 0; j < 4; j++) polyState[4+i] |= static_cast<uint32_t>(chunkKey[i*4+j]) << (j*8);
    }
    polyState[12] = 0; polyState[13] = static_cast<uint32_t>(nonce);
    polyState[14] = static_cast<uint32_t>(nonce >> 32); polyState[15] = 0;
    
    uint32_t polyBlock[16], polyKeystream[16];
    std::memcpy(polyBlock, polyState, sizeof(polyBlock)); chachaBlock(polyBlock, polyKeystream);
    
    uint8_t polyKey[32];
    for (int i = 0; i < 32; i++) polyKey[i] = static_cast<uint8_t>(polyKeystream[i / 4] >> (i % 4) * 8);
    
    chachaEncrypt(in, len, chunkKey, 1, nonce, out);
    poly1305Mac(out, len, polyKey, out + len);
    return true;
}

// ============================================================================
// STRUCTURES & FILE I/O
// ============================================================================

struct ArchiveHeader {
    char magic[4];         // "DCF1"
    uint32_t version;      // 4 (with ChaCha20+Poly1305 AEAD + SHA256 KDF)
    uint32_t entryCount;
    uint32_t contentCrc32;
    uint32_t headerCrc32;
};

struct ArchiveEntry {
    std::string relativePath;
    bool isDirectory;
    fs::path sourcePath;
    size_t contentSize;
};

template<typename T>
std::vector<uint8_t> toLittleEndian(T value) {
    std::vector<uint8_t> bytes(sizeof(T));
    for (size_t i = 0; i < sizeof(T); i++) { bytes[i] = static_cast<uint8_t>(value & 0xFF); value >>= 8; }
    return bytes;
}

template<typename T>
T fromLittleEndian(const uint8_t* bytes, size_t offset = 0) {
    T value = 0;
    for (size_t i = 0; i < sizeof(T); i++) value |= static_cast<T>(bytes[offset + i]) << (i * 8);
    return value;
}

// ============================================================================
// ARCHIVE CREATION (Zero-copy optimization)
// ============================================================================

void collectEntries(const fs::path& basePath, const fs::path& currentPath, std::vector<ArchiveEntry>& entries) {
    if (fs::is_directory(currentPath)) {
        entries.push_back({ fs::relative(currentPath, basePath).string(), true, currentPath, 0 });
        std::error_code ec;
        for (const auto& entry : fs::directory_iterator(currentPath, ec)) collectEntries(basePath, entry.path(), entries);
    } else if (fs::is_regular_file(currentPath)) {
        std::error_code ec;
        size_t size = fs::file_size(currentPath, ec);
        if (!ec) entries.push_back({ fs::relative(currentPath, basePath).string(), false, currentPath, size });
    }
}

void createArchive(const std::vector<fs::path>& paths, const std::string& key, fs::path outputPath, ProgressBar* bar) {
    std::vector<ArchiveEntry> entries;
    fs::path basePath = (paths.size() == 1 && fs::is_directory(paths[0])) ? paths[0].parent_path() : fs::current_path();
    if (basePath.empty()) basePath = fs::current_path();
    
    for (const auto& path : paths) collectEntries(basePath, path, entries);
    
    if (bar) bar->setStatus("Calculating size...");
    size_t totalSize = sizeof(ArchiveHeader);
    for (const auto& e : entries) totalSize += 4 + e.relativePath.size() + 1 + 8 + e.contentSize;
    if (bar) bar->setTotal(totalSize);
    
    std::ofstream outFile(outputPath, std::ios::binary);
    if (!outFile.is_open()) throw std::runtime_error("Could not open output file");

    std::vector<uint8_t> pushBuf(CHUNK_SIZE + TAG_SIZE);
    size_t pushOffset = sizeof(ArchiveHeader), fileOffset = 0;
    CRC32 contentCrc; bool headerWritten = false;
    
    ArchiveHeader headerPlaceholder = {};
    std::memcpy(headerPlaceholder.magic, MAGIC, 4); headerPlaceholder.version = VERSION;
    headerPlaceholder.entryCount = static_cast<uint32_t>(entries.size());
    std::memcpy(pushBuf.data(), &headerPlaceholder, sizeof(ArchiveHeader));
    
    auto flushBuf = [&]() {
        if (pushOffset == 0) return;
        size_t crcStart = headerWritten ? 0 : sizeof(ArchiveHeader);
        if (pushOffset > crcStart) contentCrc.update(pushBuf.data() + crcStart, pushOffset - crcStart);
        headerWritten = true;
        chachaEncryptChunk(pushBuf.data(), pushOffset, key, fileOffset / CHUNK_SIZE, pushBuf.data());
        if (fileOffset == 0) outFile.seekp(sizeof(ArchiveHeader));
        outFile.write(reinterpret_cast<const char*>(pushBuf.data()), pushOffset + TAG_SIZE);
        fileOffset += pushOffset; pushOffset = 0;
        if (bar) bar->update(fileOffset);
    };
    
    auto pushBytes = [&](const uint8_t* data, size_t len) {
        while (len > 0) {
            size_t toCopy = std::min(len, CHUNK_SIZE - pushOffset);
            std::memcpy(pushBuf.data() + pushOffset, data, toCopy);
            pushOffset += toCopy; data += toCopy; len -= toCopy;
            if (pushOffset == CHUNK_SIZE) flushBuf();
        }
    };
    
    if (bar) bar->setStatus("Building archive...");
    for (const auto& entry : entries) {
        auto pathLenBytes = toLittleEndian<uint32_t>(entry.relativePath.size());
        pushBytes(pathLenBytes.data(), 4); pushBytes(reinterpret_cast<const uint8_t*>(entry.relativePath.data()), entry.relativePath.size());
        uint8_t isDir = entry.isDirectory ? 1 : 0; pushBytes(&isDir, 1);
        auto sizeBytes = toLittleEndian<uint64_t>(entry.contentSize); pushBytes(sizeBytes.data(), 8);
        
        if (!entry.isDirectory && entry.contentSize > 0) {
            std::ifstream file(entry.sourcePath, std::ios::binary);
            if (!file.is_open()) throw std::runtime_error("Cannot read file: " + entry.sourcePath.string());
            uint64_t remaining = entry.contentSize;
            while (file && remaining > 0) {
                size_t toRead = std::min(static_cast<size_t>(remaining), CHUNK_SIZE - pushOffset);
                file.read(reinterpret_cast<char*>(pushBuf.data() + pushOffset), toRead);
                size_t readCount = file.gcount();
                if (readCount == 0) break;
                pushOffset += readCount; remaining -= readCount;
                if (pushOffset == CHUNK_SIZE) flushBuf();
            }
        }
    }
    flushBuf();
    
    ArchiveHeader finalHeader = headerPlaceholder;
    finalHeader.contentCrc32 = contentCrc.finalize();
    finalHeader.headerCrc32 = CRC32::calculate(&finalHeader, offsetof(ArchiveHeader, contentCrc32));
    
    uint8_t chunk0Key[32]; uint64_t chunk0Nonce;
    deriveKeyAndNonce(key, 0, chunk0Key, &chunk0Nonce);
    chachaEncrypt(reinterpret_cast<const uint8_t*>(&finalHeader), sizeof(finalHeader), chunk0Key, 0, chunk0Nonce, reinterpret_cast<uint8_t*>(&finalHeader));
    
    outFile.seekp(0); outFile.write(reinterpret_cast<const char*>(&finalHeader), sizeof(finalHeader));
    outFile.close();
    if (bar) bar->finish();
}

// ============================================================================
// ARCHIVE EXTRACTION
// ============================================================================

class BufferedStreamReader {
public:
    BufferedStreamReader(const fs::path& filePath, const std::string& key)
        : m_file(filePath, std::ios::binary), m_key(key), m_dataBuffer(CHUNK_SIZE), m_bufPos(0), m_bufLen(0), m_fileOffset(sizeof(ArchiveHeader)), m_eof(false), m_headerSkipDone(false) {
        m_file.seekg(sizeof(ArchiveHeader), std::ios::beg);
    }
    bool isOpen() const { return m_file.is_open(); }
    bool read(uint8_t* out, size_t count) {
        while (count > 0) {
            if (m_bufPos >= m_bufLen && !refillBuffer()) return false;
            size_t toCopy = std::min(count, m_bufLen - m_bufPos);
            std::memcpy(out, m_dataBuffer.data() + m_bufPos, toCopy);
            out += toCopy; m_bufPos += toCopy; count -= toCopy;
        }
        return true;
    }
private:
    std::ifstream m_file; std::string m_key; std::vector<uint8_t> m_dataBuffer;
    size_t m_bufPos, m_bufLen, m_fileOffset; bool m_eof, m_headerSkipDone;

    bool refillBuffer() {
        if (m_eof) return false;
        std::vector<uint8_t> rawBuffer(CHUNK_SIZE + TAG_SIZE);
        m_file.read(reinterpret_cast<char*>(rawBuffer.data()), CHUNK_SIZE + TAG_SIZE);
        size_t rawLen = static_cast<size_t>(m_file.gcount());
        if (rawLen <= TAG_SIZE) { m_eof = true; return false; }
        
        size_t dataLen = rawLen - TAG_SIZE;
        uint8_t chunkKey[32]; uint64_t nonce;
        deriveKeyAndNonce(m_key, m_fileOffset / CHUNK_SIZE, chunkKey, &nonce);
        
        uint32_t polyState[16] = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574};
        for (int i = 0; i < 8; i++) {
            polyState[4+i]=0; for (int j=0; j<4; j++) polyState[4+i] |= static_cast<uint32_t>(chunkKey[i*4+j]) << (j*8);
        }
        polyState[12] = 0; polyState[13] = static_cast<uint32_t>(nonce); polyState[14] = static_cast<uint32_t>(nonce >> 32); polyState[15] = 0;
        uint32_t polyKeystream[16]; chachaBlock(polyState, polyKeystream);
        
        uint8_t polyKey[32]; for (int i=0; i<32; i++) polyKey[i] = static_cast<uint8_t>(polyKeystream[i/4] >> (i%4)*8);
        
        uint8_t computedTag[TAG_SIZE]; poly1305Mac(rawBuffer.data(), dataLen, polyKey, computedTag);
        uint8_t res = 0; for (size_t i = 0; i < TAG_SIZE; i++) res |= rawBuffer[dataLen + i] ^ computedTag[i];
        if (res != 0) throw std::runtime_error("Poly1305 Tag verification failed. Archive is corrupt or bad key.");
        
        chachaDecrypt(rawBuffer.data(), dataLen, chunkKey, 1, nonce, m_dataBuffer.data());
        
        size_t skip = (!m_headerSkipDone && dataLen > sizeof(ArchiveHeader)) ? sizeof(ArchiveHeader) : 0;
        if (skip) { std::memmove(m_dataBuffer.data(), m_dataBuffer.data() + skip, dataLen - skip); m_headerSkipDone = true; }
        
        m_bufPos = 0; m_bufLen = dataLen - skip; m_fileOffset += dataLen;
        return true;
    }
};

bool extractArchive(const fs::path& archivePath, const std::string& key, ProgressBar* bar) {
    fs::path extractDir = archivePath.parent_path(); if (extractDir.empty()) extractDir = fs::current_path();
    std::vector<fs::path> extractedItems;
    
    if (bar) bar->setStatus("Reading header...");
    std::vector<uint8_t> headerBuf(sizeof(ArchiveHeader));
    std::ifstream headerFile(archivePath, std::ios::binary);
    if (!headerFile.is_open()) { std::cerr << "Cannot open file.\n"; return false; }
    headerFile.read(reinterpret_cast<char*>(headerBuf.data()), headerBuf.size()); headerFile.close();

    uint8_t chunk0Key[32]; uint64_t chunk0Nonce;
    deriveKeyAndNonce(key, 0, chunk0Key, &chunk0Nonce);
    chachaDecrypt(headerBuf.data(), headerBuf.size(), chunk0Key, 0, chunk0Nonce, headerBuf.data());

    ArchiveHeader header; std::memcpy(&header, headerBuf.data(), sizeof(header));
    if (std::memcmp(header.magic, MAGIC, 4) != 0 || header.version != VERSION) {
        std::cerr << "Invalid archive format or unsupported version.\n"; return false;
    }
    if (header.headerCrc32 != CRC32::calculate(headerBuf.data(), offsetof(ArchiveHeader, contentCrc32))) {
        std::cerr << "Header CRC32 check failed (wrong password or corrupt file).\n"; return false;
    }

    if (bar) { bar->setStatus("Extracting..."); bar->setTotal(fs::file_size(archivePath) - sizeof(ArchiveHeader)); }
    BufferedStreamReader reader(archivePath, key); CRC32 contentCrc;
    std::vector<uint8_t> readBuf(CHUNK_SIZE); size_t totalExtracted = 0;

    for (uint32_t i = 0; i < header.entryCount; i++) {
        uint8_t leBuf[8];
        if (!reader.read(leBuf, 4)) return false; contentCrc.update(leBuf, 4);
        uint32_t pathLen = fromLittleEndian<uint32_t>(leBuf);
        
        std::string relPath(pathLen, '\0');
        if (pathLen > 0) { reader.read(reinterpret_cast<uint8_t*>(&relPath[0]), pathLen); contentCrc.update(relPath.data(), pathLen); }
        
        uint8_t isDirByte; reader.read(&isDirByte, 1); contentCrc.update(&isDirByte, 1);
        reader.read(leBuf, 8); contentCrc.update(leBuf, 8); uint64_t contentSize = fromLittleEndian<uint64_t>(leBuf);

        fs::path fullPath = extractDir / relPath;
        if (isDirByte) { fs::create_directories(fullPath); extractedItems.push_back(fullPath); }
        else {
            fs::create_directories(fullPath.parent_path());
            std::ofstream outFile(fullPath, std::ios::binary); extractedItems.push_back(fullPath);
            uint64_t remaining = contentSize;
            while (remaining > 0) {
                size_t toRead = std::min(remaining, static_cast<uint64_t>(readBuf.size()));
                reader.read(readBuf.data(), toRead); contentCrc.update(readBuf.data(), toRead);
                outFile.write(reinterpret_cast<const char*>(readBuf.data()), toRead);
                remaining -= toRead; totalExtracted += toRead; if(bar) bar->update(totalExtracted);
            }
        }
    }

    if (bar) bar->setStatus("Verifying...");
    if (header.contentCrc32 != contentCrc.finalize()) {
        std::cerr << "Content CRC32 mismatch! Deleting extracted files...\n";
        for (auto& p : extractedItems) { std::error_code ec; fs::remove_all(p, ec); }
        if (bar) bar->finish(); return false;
    }
    if (bar) bar->finish(); return true;
}

// ============================================================================
// CLI INTERFACE
// ============================================================================

std::string getEncryptionKey(const std::string& provided) {
    if (!provided.empty()) return provided;
#ifdef _WIN32
    if (_isatty(_fileno(stdin))) {
#else
    if (isatty(fileno(stdin))) {
#endif
        std::string pwd; char ch;
        std::cout << "Enter encryption key: ";
#ifdef _WIN32
        while ((ch = _getch()) != '\r' && ch != '\n') { if (ch == '\b') { if (!pwd.empty()) { pwd.pop_back(); std::cout << "\b \b"; } } else { pwd += ch; std::cout << '*'; } }
#else
        struct termios o, n; tcgetattr(STDIN_FILENO, &o); n=o; n.c_lflag &= ~ECHO; tcsetattr(STDIN_FILENO, TCSANOW, &n);
        std::getline(std::cin, pwd); tcsetattr(STDIN_FILENO, TCSANOW, &o);
#endif
        std::cout << "\n"; return pwd.empty() ? DEFAULT_KEY : pwd;
    }
    return DEFAULT_KEY;
}

int main(int argc, char* argv[]) {
    auto waitExit = [argc]() {
#ifdef _WIN32
        if (argc == 2) { std::cout << "\nPress Enter to exit..."; std::cin.clear(); int ch; while((ch=std::cin.get())!='\n'&&ch!=EOF){} std::cin.get(); }
#endif
    };

    if (argc < 2) {
        std::cout << "DCF - Data Cryptography File Tool\nUsage:\n  dcf <file/folder> [-o out.dcf] [-p key]\n";
        waitExit(); return 1;
    }
    
    std::vector<fs::path> inputs; std::string customOutput, providedKey;
    bool forceEncrypt = false, forceDecrypt = false, noProgress = false;
    
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--encrypt") forceEncrypt = true;
        else if (arg == "--decrypt") forceDecrypt = true;
        else if (arg == "--no-progress") noProgress = true;
        else if (arg == "-o" && ++i < argc) customOutput = argv[i];
        else if (arg == "-p" && ++i < argc) providedKey = argv[i];
        else inputs.push_back(arg);
    }
    
    if (inputs.empty()) { 
        waitExit(); 
        return 1; 
    }
    
    std::string key = getEncryptionKey(providedKey);
    bool decryptMode = forceDecrypt || (!forceEncrypt && inputs.size() == 1 && inputs[0].extension() == ".dcf");
    
    if (decryptMode) {
        std::unique_ptr<ProgressBar> progress = noProgress ? nullptr : std::make_unique<ProgressBar>("Decrypting", 0);
        bool ok = extractArchive(inputs[0], key, progress.get());
        std::cout << (ok ? "Extraction complete.\n" : "Error: Extraction failed\n");
        if (!ok) {
            waitExit();
        }
        return ok ? 0 : 1;
    } else {
        fs::path outputPath = customOutput.empty() ? (inputs[0].filename().string() + ".dcf") : customOutput;
        try {
            std::unique_ptr<ProgressBar> progress = noProgress ? nullptr : std::make_unique<ProgressBar>("Encrypting", 0);
            createArchive(inputs, key, outputPath, progress.get());
            std::cout << "Created: " << outputPath.string() << " (" << fs::file_size(outputPath) << " bytes encrypted)\n";
            return 0; // Success operation: returns directly, will automatically close without user interaction
        } catch (const std::exception& e) {
            std::cerr << "Error: " << e.what() << "\n";
            std::error_code ec; fs::remove(outputPath, ec); // Cleanup bad file
            waitExit(); 
            return 1;
        }
    }
}