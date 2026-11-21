// Tests del núcleo de cifrado. Sin dependencias externas: `make test`.

#include "cifrado.hpp"

#include <cstring>
#include <fstream>
#include <iostream>
#include <random>
#include <string>
#include <vector>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <unistd.h>

using namespace cifrado;

namespace {

int g_failed = 0;
int g_checks = 0;

#define CHECK(cond)                                                            \
  do {                                                                         \
    ++g_checks;                                                                \
    if (!(cond)) {                                                             \
      ++g_failed;                                                              \
      std::cerr << "  FALLO " << __FILE__ << ":" << __LINE__ << ": " #cond     \
                << "\n";                                                       \
    }                                                                          \
  } while (0)

// Parámetros bajos para que los tests sean rápidos.
KdfParams fastKdf() {
  KdfParams p;
  p.t_cost = 1;
  p.m_cost_kib = 256;
  p.lanes = 1;
  return p;
}

Options fastOpts() {
  Options o;
  o.kdf = fastKdf();
  return o;
}

std::string readAll(const fs::path &p) {
  std::ifstream f(p, std::ios::binary);
  return {std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>()};
}

void writeAll(const fs::path &p, const std::string &data) {
  std::ofstream f(p, std::ios::binary);
  f.write(data.data(), std::streamsize(data.size()));
}

std::string randomData(size_t n, unsigned seed) {
  std::mt19937 rng(seed);
  std::string s(n, '\0');
  for (auto &c : s)
    c = char(rng());
  return s;
}

struct TempDir {
  fs::path path;
  TempDir() {
    path = fs::temp_directory_path() /
           ("cifrado-test-" + std::to_string(::getpid()) + "-" +
            std::to_string(std::random_device{}()));
    fs::create_directories(path);
  }
  ~TempDir() {
    std::error_code ec;
    fs::remove_all(path, ec);
  }
};

size_t countTempFiles(const fs::path &dir) {
  size_t n = 0;
  for (auto &e : fs::recursive_directory_iterator(dir))
    if (e.path().filename().string().find(".cifrado-tmp") != std::string::npos)
      ++n;
  return n;
}

// Reproduce el cifrado de la versión 1.x para probar la compatibilidad.
void writeLegacy(const fs::path &out, const std::string &plain,
                 const std::string &pw) {
  unsigned char salt[16], key[32], iv[16];
  RAND_bytes(salt, 16);
  PKCS5_PBKDF2_HMAC(pw.c_str(), int(pw.size()), salt, 16, 100000, EVP_sha256(), 32, key);
  PKCS5_PBKDF2_HMAC(pw.c_str(), int(pw.size()), salt, 16, 100000, EVP_sha256(), 16, iv);
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv);
  std::vector<unsigned char> ct(plain.size() + 32);
  int len = 0, total = 0;
  EVP_EncryptUpdate(ctx, ct.data(), &len,
                    reinterpret_cast<const unsigned char *>(plain.data()),
                    int(plain.size()));
  total = len;
  EVP_EncryptFinal_ex(ctx, ct.data() + total, &len);
  total += len;
  EVP_CIPHER_CTX_free(ctx);
  std::ofstream f(out, std::ios::binary);
  f.write(reinterpret_cast<char *>(salt), 16);
  f.write(reinterpret_cast<char *>(ct.data()), total);
}

// ---------------------------------------------------------------------------

void testRoundTripSizes() {
  TempDir d;
  // Incluye vacío, tamaños no múltiplos de bloque y varios chunks de 64 KiB.
  for (size_t n : {size_t(0), size_t(1), size_t(15), size_t(16), size_t(17),
                   size_t(65535), size_t(65536), size_t(200000)}) {
    fs::path src = d.path / ("f" + std::to_string(n));
    std::string data = randomData(n, unsigned(n));
    writeAll(src, data);
    Session s("secreto", fastKdf());
    CHECK(s.encryptFile(src, src.string() + ".enc", false) == Status::Ok);
    CHECK(fs::file_size(src.string() + ".enc") == n + 48 + 16);
    fs::path back = d.path / ("back" + std::to_string(n));
    Session s2("secreto");
    bool legacy = true;
    CHECK(s2.decryptFile(src.string() + ".enc", back, false, nullptr, &legacy) ==
          Status::Ok);
    CHECK(!legacy);
    CHECK(readAll(back) == data);
  }
  CHECK(countTempFiles(d.path) == 0);
}

void testWrongPassword() {
  TempDir d;
  fs::path src = d.path / "a.txt", enc = d.path / "a.txt.enc";
  writeAll(src, "hola mundo");
  Session s("buena", fastKdf());
  CHECK(s.encryptFile(src, enc, false) == Status::Ok);
  fs::remove(src);

  Session bad("mala");
  CHECK(bad.decryptFile(enc, src, false) == Status::WrongPasswordOrCorrupt);
  CHECK(!fs::exists(src));
  CHECK(fs::exists(enc));
  CHECK(countTempFiles(d.path) == 0);
}

void testTamperDetected() {
  TempDir d;
  fs::path src = d.path / "a.bin", enc = d.path / "a.bin.enc";
  writeAll(src, randomData(1000, 7));
  Session s("pw", fastKdf());
  CHECK(s.encryptFile(src, enc, false) == Status::Ok);
  std::string orig = readAll(enc);

  // Se modifica un byte del contenido, del tag y de la cabecera.
  for (size_t pos : {size_t(100), orig.size() - 1, size_t(30)}) {
    std::string t = orig;
    t[pos] ^= 0x01;
    writeAll(enc, t);
    fs::path out = d.path / "out";
    Session s2("pw");
    CHECK(s2.decryptFile(enc, out, false) == Status::WrongPasswordOrCorrupt);
    CHECK(!fs::exists(out));
  }

  // Truncado.
  writeAll(enc, orig.substr(0, orig.size() - 5));
  Session s3("pw");
  CHECK(s3.decryptFile(enc, d.path / "out", false) != Status::Ok);
  CHECK(countTempFiles(d.path) == 0);
}

void testMaliciousHeaderRejected() {
  TempDir d;
  fs::path src = d.path / "a", enc = d.path / "a.enc";
  writeAll(src, "x");
  Session s("pw", fastKdf());
  CHECK(s.encryptFile(src, enc, false) == Status::Ok);
  std::string t = readAll(enc);
  // m_cost = 0xFFFFFFFF KiB: debe rechazarse sin intentar reservar memoria.
  t[12] = t[13] = t[14] = t[15] = char(0xff);
  writeAll(enc, t);
  Session s2("pw");
  CHECK(s2.decryptFile(enc, d.path / "o", false) == Status::InvalidFormat);
}

void testNoOverwrite() {
  TempDir d;
  fs::path src = d.path / "a.txt", enc = d.path / "a.txt.enc";
  writeAll(src, "nuevo");
  writeAll(enc, "ya existía");
  Session s("pw", fastKdf());
  CHECK(s.encryptFile(src, enc, false) == Status::AlreadyExists);
  CHECK(readAll(enc) == "ya existía");
  CHECK(s.encryptFile(src, enc, true) == Status::Ok);

  // Al descifrar, un archivo existente con el nombre de destino no se toca,
  // ni siquiera si la contraseña es incorrecta.
  writeAll(src, "archivo del usuario");
  Session bad("otra");
  CHECK(bad.decryptFile(enc, src, false) == Status::AlreadyExists);
  CHECK(readAll(src) == "archivo del usuario");
}

void testLegacyFormat() {
  TempDir d;
  fs::path enc = d.path / "viejo.txt.enc";
  writeLegacy(enc, "contenido antiguo", "clave");

  Options o = fastOpts();
  std::vector<FileResult> results;
  Summary s = process({d.path}, "clave", Mode::Decrypt, o,
                      [&](const FileResult &r, size_t, size_t) { results.push_back(r); });
  CHECK(s.ok == 1);
  CHECK(readAll(d.path / "viejo.txt") == "contenido antiguo");
  CHECK(results.size() == 1 && results[0].legacy);
  // Por seguridad, el .enc antiguo se conserva.
  CHECK(fs::exists(enc));
}

void testFolderProcess() {
  TempDir d;
  fs::create_directories(d.path / "sub" / "deep");
  writeAll(d.path / "a.txt", "A");
  writeAll(d.path / "sub" / "b.txt", "B");
  writeAll(d.path / "sub" / "deep" / "c.txt", "C");

  // Un enlace simbólico a un archivo fuera de la carpeta no debe tocarse.
  TempDir outside;
  writeAll(outside.path / "fuera.txt", "FUERA");
  fs::create_symlink(outside.path / "fuera.txt", d.path / "enlace.txt");

  Options o = fastOpts();
  Summary s = process({d.path}, "pw", Mode::Encrypt, o);
  CHECK(s.ok == 3);
  CHECK(s.failed == 0);
  CHECK(fs::exists(d.path / "a.txt.enc"));
  CHECK(!fs::exists(d.path / "a.txt"));
  CHECK(fs::exists(d.path / "sub" / "deep" / "c.txt.enc"));
  CHECK(readAll(outside.path / "fuera.txt") == "FUERA");
  CHECK(fs::is_symlink(d.path / "enlace.txt"));

  // Volver a cifrar no cifra dos veces.
  Summary again = process({d.path}, "pw", Mode::Encrypt, o);
  CHECK(again.ok == 0);

  Summary dec = process({d.path}, "pw", Mode::Decrypt, o);
  CHECK(dec.ok == 3);
  CHECK(readAll(d.path / "sub" / "b.txt") == "B");
  CHECK(!fs::exists(d.path / "sub" / "b.txt.enc"));
}

void testSingleFileAndKeep() {
  TempDir d;
  fs::path f = d.path / "solo.pdf";
  writeAll(f, "PDF");
  Options o = fastOpts();
  o.keepOriginal = true;
  Summary s = process({f}, "pw", Mode::Encrypt, o);
  CHECK(s.ok == 1);
  CHECK(fs::exists(f));
  CHECK(fs::exists(d.path / "solo.pdf.enc"));

  // Un archivo explícito con el modo equivocado se omite.
  Summary s2 = process({d.path / "solo.pdf.enc"}, "pw", Mode::Encrypt, o);
  CHECK(s2.skipped == 1 && s2.ok == 0);

  Summary s3 = process({d.path / "noexiste"}, "pw", Mode::Encrypt, o);
  CHECK(s3.failed == 1);
}

void testCancel() {
  TempDir d;
  writeAll(d.path / "a", "1");
  writeAll(d.path / "b", "2");
  std::atomic<bool> cancel{true};
  Summary s = process({d.path}, "pw", Mode::Encrypt, fastOpts(), {}, &cancel);
  CHECK(s.cancelled);
  CHECK(s.ok == 0);
  CHECK(fs::exists(d.path / "a"));
  CHECK(countTempFiles(d.path) == 0);
}

void testByteProgress() {
  TempDir d;
  writeAll(d.path / "a", randomData(150000, 1));
  writeAll(d.path / "b", randomData(10, 2));
  writeAll(d.path / "c", "");
  for (Mode m : {Mode::Encrypt, Mode::Decrypt}) {
    std::vector<std::pair<uintmax_t, uintmax_t>> calls;
    Summary s = process({d.path}, "pw", m, fastOpts(), {}, nullptr,
                        [&](uintmax_t done, uintmax_t total) { calls.push_back({done, total}); });
    CHECK(s.ok == 3);
    CHECK(calls.size() > 3); // avanza también dentro del archivo grande
    bool monotonic = true;
    for (size_t i = 1; i < calls.size(); ++i)
      monotonic &= calls[i].first >= calls[i - 1].first;
    CHECK(monotonic);
    CHECK(!calls.empty() && calls.back().first == calls.back().second);
    CHECK(calls.back().second == (m == Mode::Encrypt ? 150010u : 150010u + 3 * 64));
  }
}

void testDefaultArgon2() {
  // Comprueba que los parámetros por defecto funcionan en este OpenSSL.
  TempDir d;
  writeAll(d.path / "x", "x");
  Session s("pw");
  CHECK(s.encryptFile(d.path / "x", d.path / "x.enc", false) == Status::Ok);
  Session s2("pw");
  CHECK(s2.decryptFile(d.path / "x.enc", d.path / "y", false) == Status::Ok);
  CHECK(readAll(d.path / "y") == "x");
}

} // namespace

int main() {
  struct {
    const char *name;
    void (*fn)();
  } tests[] = {
      {"ida y vuelta (varios tamaños)", testRoundTripSizes},
      {"contraseña incorrecta", testWrongPassword},
      {"detección de manipulación", testTamperDetected},
      {"cabecera maliciosa", testMaliciousHeaderRejected},
      {"no sobrescribir", testNoOverwrite},
      {"formato antiguo", testLegacyFormat},
      {"carpeta recursiva y enlaces", testFolderProcess},
      {"archivo individual y --keep", testSingleFileAndKeep},
      {"cancelación", testCancel},
      {"progreso por bytes", testByteProgress},
      {"Argon2id por defecto", testDefaultArgon2},
  };
  for (auto &t : tests) {
    int before = g_failed;
    t.fn();
    std::cout << (g_failed == before ? "[ OK ] " : "[FAIL] ") << t.name << "\n";
  }
  std::cout << "\n" << g_checks << " comprobaciones, " << g_failed << " fallos\n";
  return g_failed == 0 ? 0 : 1;
}
