// keyscan.cpp - do khoa AES trong anh bo nho (memory dump), ban C++ cua keyscan.py.

#include <array>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <random>
#include <set>
#include <string>
#include <vector>

using u8 = uint8_t;

// ---------- AES key schedule ----------
static const u8 SBOX[256] = {
  0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
  0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
  0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
  0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
  0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
  0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
  0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
  0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
  0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
  0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
  0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
  0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
  0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
  0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
  0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
  0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16};
static const u8 RCON[14] = {0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36,0x6C,0xD8,0xAB,0x4D};

static int sched_len(int bits) { return bits == 128 ? 176 : bits == 192 ? 208 : 240; }

// Khoa nk word -> key schedule (176/208/240 byte) ghi vao out.
static void expand_key(const u8* key, int klen, u8* out) {
  int nk = klen / 4, nr = nk + 6, total = 4 * (nr + 1);
  std::memcpy(out, key, klen);
  for (int i = nk; i < total; i++) {
    u8 t[4];
    std::memcpy(t, out + 4 * (i - 1), 4);
    if (i % nk == 0) {
      u8 r0 = t[0];
      t[0] = SBOX[t[1]] ^ RCON[i / nk - 1]; t[1] = SBOX[t[2]]; t[2] = SBOX[t[3]]; t[3] = SBOX[r0];
    } else if (nk > 6 && i % nk == 4) {
      for (int j = 0; j < 4; j++) t[j] = SBOX[t[j]];
    }
    for (int j = 0; j < 4; j++) out[4 * i + j] = out[4 * (i - nk) + j] ^ t[j];
  }
}

// Kiem tra region (da byteswap neu can) co phai key schedule hop le khong.
// So sanh theo tung word va dung som de nhanh.
static bool is_schedule(const u8* region, int klen) {
  int nk = klen / 4, nr = nk + 6, total = 4 * (nr + 1);
  for (int i = nk; i < total; i++) {
    u8 t[4];
    std::memcpy(t, region + 4 * (i - 1), 4);
    if (i % nk == 0) {
      u8 r0 = t[0];
      t[0] = SBOX[t[1]] ^ RCON[i / nk - 1]; t[1] = SBOX[t[2]]; t[2] = SBOX[t[3]]; t[3] = SBOX[r0];
    } else if (nk > 6 && i % nk == 4) {
      for (int j = 0; j < 4; j++) t[j] = SBOX[t[j]];
    }
    for (int j = 0; j < 4; j++)
      if (region[4 * i + j] != (region[4 * (i - nk) + j] ^ t[j])) return false;
  }
  return true;
}

// ---------- entropy Shannon ----------
static double LOG2[257];  // LOG2[c] = c*log2(c), tinh san
static void init_log() { for (int c = 0; c <= 256; c++) LOG2[c] = c ? c * std::log2((double)c) : 0.0; }

// Entropy Shannon (bit/byte) cua n byte.
static double shannon(const u8* p, int n) {
  u8 cnt[256] = {0};
  u8 seen[32]; int ns = 0;           // n <= 32 -> toi da 32 gia tri khac nhau
  for (int i = 0; i < n; i++) if (cnt[p[i]]++ == 0) seen[ns++] = p[i];
  double s = 0;
  for (int i = 0; i < ns; i++) s += LOG2[cnt[seen[i]]];
  return std::log2((double)n) - s / n;   // H = log2(n) - (1/n)*sum c*log2(c)
}

static void byteswap_words(const u8* in, u8* out, int len) {
  for (int i = 0; i + 3 < len; i += 4) {
    out[i] = in[i + 3]; out[i + 1] = in[i + 2]; out[i + 2] = in[i + 1]; out[i + 3] = in[i];
  }
}

// ---------- quet ----------
struct Found { uint64_t off; int bits; std::string key_hex; };

struct Opts {
  std::vector<int> bits{128, 192, 256};
  bool use_entropy = true;
  double min_entropy = -1;           // <0 -> mac dinh log2(klen)-1
  bool swap = false;
};

static std::string hexs(const u8* p, int n) {
  static const char* H = "0123456789abcdef";
  std::string s; s.reserve(2 * n);
  for (int i = 0; i < n; i++) { s += H[p[i] >> 4]; s += H[p[i] & 15]; }
  return s;
}

// Quet mot buffer; base = offset cua buf[0] trong file. Chi xet offset < limit
static void scan_buf(const u8* buf, size_t n, uint64_t base, size_t limit, const Opts& o,
                     std::vector<Found>& found, std::set<std::string>& seen) {
  u8 tmp[240];
  for (int bits : o.bits) {
    int klen = bits / 8, slen = sched_len(bits);
    double thr = o.min_entropy >= 0 ? o.min_entropy : std::log2((double)klen) - 1.0;
    // Entropy cua so truot: giu bang dem cua klen byte hien tai va tong c*log2(c);
    // moi lan dich 1 byte chi cap nhat 2 byte -> O(1) moi offset.
    // H = log2(klen) - S/klen  =>  H >= thr  <=>  S <= smax
    double smax = (std::log2((double)klen) - thr) * klen + 1e-9;
    int cnt[256] = {0};
    double S = 0;
    if (o.use_entropy && n >= (size_t)klen)
      for (int i = 0; i < klen; i++) { u8 b = buf[i]; S += LOG2[cnt[b] + 1] - LOG2[cnt[b]]; cnt[b]++; }
    for (size_t off = 0; off < limit && off + slen <= n; off++) {
      const u8* p = buf + off;
      if (o.use_entropy) {
        if (off) {                       // bo byte off-1, them byte off+klen-1
          u8 b = buf[off - 1];      S += LOG2[cnt[b] - 1] - LOG2[cnt[b]]; cnt[b]--;
          b = buf[off + klen - 1];  S += LOG2[cnt[b] + 1] - LOG2[cnt[b]]; cnt[b]++;
        }
        // byteswap trong word khong doi tap byte -> entropy tinh tren du lieu goc van dung
        if (S > smax) continue;
      }
      const u8* region = p;
      if (o.swap) { byteswap_words(p, tmp, slen); region = tmp; }
      if (is_schedule(region, klen)) {
        std::string kh = hexs(region, klen);
        if (seen.insert(kh).second) found.push_back({base + off, bits, kh});
      }
    }
  }
}

static bool scan_file(const char* path, const Opts& o, std::vector<Found>& found, uint64_t& total) {
  FILE* f = std::fopen(path, "rb");
  if (!f) { std::fprintf(stderr, "[!] khong mo duoc %s\n", path); return false; }
  const size_t CHUNK = 64u << 20, OVER = 240;   // doc tung 64 MB, chong lan 240 byte
  std::vector<u8> buf(CHUNK + OVER);
  std::set<std::string> seen;
  size_t have = 0; uint64_t base = 0; total = 0;
  for (;;) {
    size_t r = std::fread(buf.data() + have, 1, buf.size() - have, f);
    total += r;
    size_t n = have + r;
    bool eof = r < buf.size() - have;
    if (n == 0) break;
    size_t limit = eof ? n : n - OVER;
    scan_buf(buf.data(), n, base, limit, o, found, seen);
    if (eof) break;
    std::memmove(buf.data(), buf.data() + limit, n - limit);
    have = n - limit; base += limit;
  }
  std::fclose(f);
  return true;
}

// ---------- JSON ----------
static std::string jstr(const std::string& s) {
  std::string r = "\"";
  for (char c : s) {
    if (c == '"' || c == '\\') { r += '\\'; r += c; }
    else if ((unsigned char)c < 0x20) { char b[8]; std::snprintf(b, sizeof b, "\\u%04x", c); r += b; }
    else r += c;
  }
  return r + "\"";
}

// ---------- self-test ----------
static int selftest() {
  int fail = 0;
  auto check = [&](bool ok, const char* name) {
    std::printf("  [%s] %s\n", ok ? "PASS" : "FAIL", name); if (!ok) fail++;
  };
  // 1. FIPS-197 AES-128: w[43] = b6630ca6
  u8 k128[16] = {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};
  u8 s[240];
  expand_key(k128, 16, s);
  check(hexs(s + 172, 4) == "b6630ca6", "FIPS-197 AES-128 key schedule (w[43]=b6630ca6)");
  // 2. FIPS-197 AES-256 (Appendix A.3): w[59] = 706c631e
  u8 k256[32] = {0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,
                 0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4};
  expand_key(k256, 32, s);
  check(hexs(s + 236, 4) == "706c631e", "FIPS-197 AES-256 key schedule (w[59]=706c631e)");
  // 3. FIPS-197 AES-192 (Appendix A.2): w[51] = 01002202
  u8 k192[24] = {0x8e,0x73,0xb0,0xf7,0xda,0x0e,0x64,0x52,0xc8,0x10,0xf3,0x2b,
                 0x80,0x90,0x79,0xe5,0x62,0xf8,0xea,0xd2,0x52,0x2c,0x6b,0x7b};
  expand_key(k192, 24, s);
  check(hexs(s + 204, 4) == "01002202", "FIPS-197 AES-192 key schedule (w[51]=01002202)");
  // 4. Entropy
  u8 z[16] = {0};
  check(shannon(z, 16) == 0.0, "entropy 16 byte zero = 0");
  check(shannon(k128, 16) >= 3.0, "entropy khoa FIPS >= nguong 3.0");
  // 5. Cay khoa vao buffer nhieu zero + nhieu ngau nhien, quet lai phai ra dung
  std::mt19937 rng(1234);
  std::vector<u8> buf(1 << 20, 0);
  for (size_t i = 0; i < buf.size() / 2; i++) buf[i] = (u8)rng();
  u8 key[32]; for (auto& b : key) b = (u8)rng();
  expand_key(key, 16, buf.data() + 300000);            // AES-128 giua vung ngau nhien
  expand_key(key, 32, buf.data() + 700000);            // AES-256 giua vung zero
  expand_key(key, 24, s); byteswap_words(s, buf.data() + 800000, 208);  // AES-192 dao byte
  Opts o; std::vector<Found> f; std::set<std::string> seen;
  scan_buf(buf.data(), buf.size(), 0, buf.size(), o, f, seen);
  bool a = false, b = false;
  for (auto& x : f) { if (x.off == 300000 && x.bits == 128) a = true; if (x.off == 700000 && x.bits == 256) b = true; }
  check(a, "tim duoc AES-128 tai 0x493e0");
  check(b, "tim duoc AES-256 tai 0xaae60");
  check(f.size() == 2, "khong bao nham (dung 2 khoa, che do thuong)");
  Opts os; os.swap = true; std::vector<Found> g; std::set<std::string> seen2;
  scan_buf(buf.data(), buf.size(), 0, buf.size(), os, g, seen2);
  bool c = false; for (auto& x : g) if (x.off == 800000 && x.bits == 192) c = true;
  check(c, "--byteswap tim duoc AES-192 dao byte tai 0xc3500");
  // 6. Che do khong loc phai ra cung ket qua
  Opts on; on.use_entropy = false; std::vector<Found> h; std::set<std::string> seen3;
  scan_buf(buf.data(), buf.size(), 0, buf.size(), on, h, seen3);
  check(h.size() == f.size(), "--no-entropy ra cung so khoa");
  std::printf("%s\n", fail ? "[!] SELFTEST FAIL" : "[=] SELFTEST PASS");
  return fail ? 1 : 0;
}

// ---------- main ----------
static void usage() {
  std::fprintf(stderr,
    "Cach dung: keyscan <dump> [--bits 128 192 256] [--out keys.json] [--baseline clean.vmem]\n"
    "                  [--source TEN] [--dump-time ISO] [--pid N] [--scope file|process]\n"
    "                  [--no-entropy] [--min-entropy X] [--byteswap]\n"
    "           keyscan --selftest\n");
}

int main(int argc, char** argv) {
  init_log();
  Opts o;
  std::string dump, out, baseline, source, dump_time, scope;
  long pid = -1;
  bool bits_set = false;
  for (int i = 1; i < argc; i++) {
    std::string a = argv[i];
    auto need = [&]() -> std::string {
      if (i + 1 >= argc) { usage(); std::exit(2); }
      return argv[++i];
    };
    if (a == "--selftest") return selftest();
    else if (a == "--bits") {
      if (!bits_set) { o.bits.clear(); bits_set = true; }
      while (i + 1 < argc && argv[i + 1][0] != '-') {
        int b = std::atoi(argv[++i]);
        if (b != 128 && b != 192 && b != 256) { std::fprintf(stderr, "[!] --bits chi nhan 128/192/256\n"); return 2; }
        o.bits.push_back(b);
      }
    }
    else if (a == "--out") out = need();
    else if (a == "--baseline") baseline = need();
    else if (a == "--source") source = need();
    else if (a == "--dump-time") dump_time = need();
    else if (a == "--pid") pid = std::atol(need().c_str());
    else if (a == "--scope") scope = need();
    else if (a == "--no-entropy") o.use_entropy = false;
    else if (a == "--min-entropy") o.min_entropy = std::atof(need().c_str());
    else if (a == "--byteswap") o.swap = true;
    else if (a == "-h" || a == "--help") { usage(); return 0; }
    else if (a[0] == '-') { std::fprintf(stderr, "[!] tham so la: %s\n", a.c_str()); usage(); return 2; }
    else dump = a;
  }
  if (dump.empty() || o.bits.empty()) { usage(); return 2; }

  std::vector<Found> found;
  uint64_t total = 0;
  auto t0 = std::chrono::steady_clock::now();
  if (!scan_file(dump.c_str(), o, found, total)) return 1;
  double dt = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();

  std::set<std::string> base_keys;
  if (!baseline.empty()) {
    std::vector<Found> bf; uint64_t bt;
    if (!scan_file(baseline.c_str(), o, bf, bt)) return 1;
    for (auto& x : bf) base_keys.insert(x.key_hex);
    std::vector<Found> keep;
    for (auto& x : found) if (!base_keys.count(x.key_hex)) keep.push_back(x);
    found.swap(keep);
  }

  if (scope.empty()) scope = pid >= 0 ? "process" : "file";
  if (source.empty()) {
    size_t p = dump.find_last_of("/\\");
    source = p == std::string::npos ? dump : dump.substr(p + 1);
  }

  char loc[64];
  if (!o.use_entropy) std::snprintf(loc, sizeof loc, "off");
  else if (o.min_entropy >= 0) std::snprintf(loc, sizeof loc, "shannon>=%.2f", o.min_entropy);
  else std::snprintf(loc, sizeof loc, "shannon>=log2(len)-1");
  std::printf("[=] quet %llu byte trong %.2fs (loc tho=%s, byteswap=%s)\n",
              (unsigned long long)total, dt, loc, o.swap ? "on" : "off");
  if (!baseline.empty()) std::printf("[=] loai %zu khoa co trong baseline\n", base_keys.size());
  for (auto& x : found) {
    char ofs[32]; std::snprintf(ofs, sizeof ofs, "0x%llx", (unsigned long long)x.off);
    std::printf("    + %3d-bit @ %10s  %s\n", x.bits, ofs, x.key_hex.c_str());
  }
  std::printf("[=] tong: %zu khoa moi\n", found.size());

  if (!out.empty()) {
    FILE* f = std::fopen(out.c_str(), "w");
    if (!f) { std::fprintf(stderr, "[!] khong ghi duoc %s\n", out.c_str()); return 1; }
    std::fprintf(f, "{\n  \"schema\": 1,\n  \"keys\": [");
    for (size_t i = 0; i < found.size(); i++) {
      auto& x = found[i];
      std::fprintf(f, "%s\n    {\n", i ? "," : "");
      std::fprintf(f, "      \"source\": %s,\n", jstr(source).c_str());
      std::fprintf(f, "      \"dump_time\": %s,\n", dump_time.empty() ? "null" : jstr(dump_time).c_str());
      std::fprintf(f, "      \"offset\": \"0x%llx\",\n", (unsigned long long)x.off);
      std::fprintf(f, "      \"bits\": %d,\n", x.bits);
      std::fprintf(f, "      \"key_hex\": \"%s\",\n", x.key_hex.c_str());
      std::fprintf(f, "      \"tool\": \"keyscan\",\n");
      if (pid >= 0) std::fprintf(f, "      \"pid\": %ld,\n", pid);
      else std::fprintf(f, "      \"pid\": null,\n");
      std::fprintf(f, "      \"scope\": %s\n    }", jstr(scope).c_str());
    }
    std::fprintf(f, "%s]\n}\n", found.empty() ? "" : "\n  ");
    std::fclose(f);
    std::printf("[=] ghi -> %s\n", out.c_str());
  }
  return 0;
}
