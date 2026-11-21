#include "cifrado.hpp"

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <memory>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/thread.h>

namespace cifrado {

namespace {

constexpr size_t KEY_SIZE = 32;
constexpr size_t SALT_SIZE = 16;
constexpr size_t GCM_IV_SIZE = 12;
constexpr size_t TAG_SIZE = 16;
constexpr size_t HEADER_SIZE = 48;
constexpr size_t CHUNK = 64 * 1024;
constexpr unsigned char MAGIC[4] = {'C', 'F', 'R', 'D'};
constexpr uint8_t FORMAT_VERSION = 1;
constexpr uint8_t KDF_ARGON2ID = 1;

// Límites para no aceptar cabeceras maliciosas que pidan recursos absurdos.
constexpr uint32_t MAX_T_COST = 64;
constexpr uint32_t MAX_M_COST_KIB = 4u * 1024 * 1024; // 4 GiB
constexpr uint32_t MAX_LANES = 64;

// Formato antiguo (v0)
constexpr size_t LEGACY_IV_SIZE = 16;
constexpr int LEGACY_PBKDF2_ITER = 100000;

constexpr const char *TMP_SUFFIX = ".cifrado-tmp";

struct CtxDeleter {
  void operator()(EVP_CIPHER_CTX *c) const { EVP_CIPHER_CTX_free(c); }
};
using CipherCtx = std::unique_ptr<EVP_CIPHER_CTX, CtxDeleter>;

// Borra un buffer de forma que el compilador no lo optimice.
template <size_t N> struct SecureBuf {
  unsigned char data[N] = {};
  ~SecureBuf() { OPENSSL_cleanse(data, N); }
};

struct SecureVec {
  std::vector<unsigned char> v;
  explicit SecureVec(size_t n) : v(n) {}
  ~SecureVec() { OPENSSL_cleanse(v.data(), v.size()); }
  unsigned char *data() { return v.data(); }
};

void putU32(unsigned char *p, uint32_t v) {
  p[0] = v & 0xff;
  p[1] = (v >> 8) & 0xff;
  p[2] = (v >> 16) & 0xff;
  p[3] = (v >> 24) & 0xff;
}

uint32_t getU32(const unsigned char *p) {
  return uint32_t(p[0]) | (uint32_t(p[1]) << 8) | (uint32_t(p[2]) << 16) |
         (uint32_t(p[3]) << 24);
}

bool cancelled(const std::atomic<bool> *c) {
  return c && c->load(std::memory_order_relaxed);
}

std::string randomHex(size_t bytes) {
  std::vector<unsigned char> b(bytes);
  if (RAND_bytes(b.data(), int(bytes)) != 1) {
    // No es material criptográfico, solo un nombre único.
    for (auto &x : b)
      x = static_cast<unsigned char>(std::rand());
  }
  static const char *hex = "0123456789abcdef";
  std::string s;
  for (auto x : b) {
    s += hex[x >> 4];
    s += hex[x & 0xf];
  }
  return s;
}

void fsyncDir(const fs::path &dir) {
  int fd = ::open(dir.empty() ? "." : dir.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (fd >= 0) {
    ::fsync(fd);
    ::close(fd);
  }
}

// Archivo de salida temporal en la misma carpeta que el destino. Si no se
// llama a commit(), se borra al destruirse: nunca quedan archivos a medias.
class TempOutput {
public:
  explicit TempOutput(fs::path finalPath) : final_(std::move(finalPath)) {}

  ~TempOutput() {
    if (fd_ >= 0)
      ::close(fd_);
    if (!committed_ && !tmp_.empty())
      ::unlink(tmp_.c_str());
  }

  bool open() {
    fs::path dir = final_.parent_path();
    for (int attempt = 0; attempt < 5; ++attempt) {
      tmp_ = dir / ("." + final_.filename().string() + "." + randomHex(6) +
                    TMP_SUFFIX);
      // 0600: el resultado (cifrado o descifrado) solo es legible por el dueño.
      fd_ = ::open(tmp_.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
      if (fd_ >= 0)
        return true;
      if (errno != EEXIST)
        break;
    }
    tmp_.clear();
    return false;
  }

  bool write(const unsigned char *p, size_t n) {
    while (n > 0) {
      ssize_t w = ::write(fd_, p, n);
      if (w < 0) {
        if (errno == EINTR)
          continue;
        return false;
      }
      p += w;
      n -= size_t(w);
    }
    return true;
  }

  Status commit(bool overwrite) {
    if (::fsync(fd_) != 0 || ::close(fd_) != 0) {
      fd_ = -1;
      return Status::WriteError;
    }
    fd_ = -1;

    if (overwrite) {
      if (::rename(tmp_.c_str(), final_.c_str()) != 0)
        return Status::WriteError;
    } else {
      // Mover sin reemplazar, de forma atómica si el sistema lo permite.
      if (::renameat2(AT_FDCWD, tmp_.c_str(), AT_FDCWD, final_.c_str(),
                      RENAME_NOREPLACE) != 0) {
        if (errno == EEXIST)
          return Status::AlreadyExists;
        if (errno != EINVAL && errno != ENOSYS)
          return Status::WriteError;
        // El sistema de archivos no soporta RENAME_NOREPLACE (p. ej. exFAT).
        std::error_code ec;
        if (fs::exists(final_, ec))
          return Status::AlreadyExists;
        if (::rename(tmp_.c_str(), final_.c_str()) != 0)
          return Status::WriteError;
      }
    }
    committed_ = true;
    fsyncDir(final_.parent_path());
    return Status::Ok;
  }

private:
  fs::path final_;
  fs::path tmp_;
  int fd_ = -1;
  bool committed_ = false;
};

bool readExact(std::ifstream &in, unsigned char *p, size_t n) {
  in.read(reinterpret_cast<char *>(p), std::streamsize(n));
  return size_t(in.gcount()) == n;
}

bool outputBlocked(const fs::path &out, bool overwrite) {
  std::error_code ec;
  return !overwrite && fs::exists(fs::symlink_status(out, ec));
}

void enableArgonThreads() {
  static bool done = [] {
    OSSL_set_max_threads(nullptr, 4);
    return true;
  }();
  (void)done;
}

} // namespace

// ---------------------------------------------------------------------------

std::string statusText(Status s) {
  switch (s) {
  case Status::Ok: return "correcto";
  case Status::Skipped: return "omitido";
  case Status::NotFound: return "no existe";
  case Status::AlreadyExists: return "el destino ya existe (usa --force para sobrescribir)";
  case Status::ReadError: return "error de lectura";
  case Status::WriteError: return "error de escritura";
  case Status::WrongPasswordOrCorrupt: return "contraseña incorrecta o archivo dañado/modificado";
  case Status::InvalidFormat: return "no es un archivo cifrado válido";
  case Status::CryptoError: return "error interno de cifrado";
  case Status::Cancelled: return "cancelado";
  }
  return "desconocido";
}

bool isFailure(Status s) {
  return s != Status::Ok && s != Status::Skipped && s != Status::Cancelled;
}

fs::path outputPathFor(const fs::path &source, Mode mode) {
  if (mode == Mode::Encrypt)
    return fs::path(source.string() + ENC_EXT);
  return source.parent_path() / source.stem();
}

Plan planFiles(const std::vector<fs::path> &targets, Mode mode) {
  Plan plan;
  auto wanted = [&](const fs::path &p) {
    bool isEnc = p.extension() == ENC_EXT;
    return mode == Mode::Encrypt ? !isEnc : isEnc;
  };
  auto isTemp = [](const fs::path &p) {
    const std::string name = p.filename().string();
    const std::string suf = TMP_SUFFIX;
    return name.size() >= suf.size() &&
           name.compare(name.size() - suf.size(), suf.size(), suf) == 0;
  };
  auto skip = [&](const fs::path &p, Status st, std::string why) {
    FileResult r;
    r.source = p;
    r.status = st;
    r.detail = std::move(why);
    plan.skipped.push_back(std::move(r));
  };

  for (const auto &t : targets) {
    std::error_code ec;
    auto st = fs::symlink_status(t, ec);
    if (ec || !fs::exists(st)) {
      skip(t, Status::NotFound, "la ruta no existe");
      continue;
    }
    if (fs::is_symlink(st)) {
      skip(t, Status::Skipped, "es un enlace simbólico");
      continue;
    }
    if (fs::is_regular_file(st)) {
      if (!wanted(t)) {
        skip(t, Status::Skipped,
             mode == Mode::Encrypt ? "ya tiene extensión .enc"
                                   : "no tiene extensión .enc");
        continue;
      }
      plan.jobs.push_back({t, outputPathFor(t, mode)});
      continue;
    }
    if (!fs::is_directory(st)) {
      skip(t, Status::Skipped, "no es un archivo regular ni una carpeta");
      continue;
    }

    // Se recolecta todo antes de modificar nada: crear/borrar archivos
    // mientras se recorre la carpeta tiene comportamiento no especificado.
    std::vector<fs::path> found;
    fs::recursive_directory_iterator it(
        t, fs::directory_options::skip_permission_denied, ec);
    if (ec) {
      skip(t, Status::ReadError, ec.message());
      continue;
    }
    for (auto end = fs::recursive_directory_iterator(); it != end;
         it.increment(ec)) {
      if (ec)
        break;
      const auto &e = *it;
      std::error_code ec2;
      if (e.is_symlink(ec2) || !e.is_regular_file(ec2))
        continue;
      if (isTemp(e.path()) || !wanted(e.path()))
        continue;
      found.push_back(e.path());
    }
    if (ec)
      skip(t, Status::ReadError, "no se pudo recorrer completa: " + ec.message());
    std::sort(found.begin(), found.end());
    for (auto &p : found)
      plan.jobs.push_back({p, outputPathFor(p, mode)});
  }
  return plan;
}

// ---------------------------------------------------------------------------

Session::Session(std::string password, KdfParams params)
    : password_(std::move(password)), params_(params) {}

Session::~Session() {
  OPENSSL_cleanse(password_.data(), password_.size());
  OPENSSL_cleanse(salt_, sizeof salt_);
  for (auto &kv : keyCache_)
    OPENSSL_cleanse(kv.second.data(), kv.second.size());
}

bool Session::ensureEncryptSalt() {
  if (!haveSalt_)
    haveSalt_ = RAND_bytes(salt_, SALT_SIZE) == 1;
  return haveSalt_;
}

bool Session::deriveKey(const unsigned char *salt, const KdfParams &p,
                        unsigned char *key) {
  std::string cacheKey(reinterpret_cast<const char *>(salt), SALT_SIZE);
  unsigned char pb[12];
  putU32(pb, p.t_cost);
  putU32(pb + 4, p.m_cost_kib);
  putU32(pb + 8, p.lanes);
  cacheKey.append(reinterpret_cast<char *>(pb), sizeof pb);

  auto it = keyCache_.find(cacheKey);
  if (it != keyCache_.end()) {
    std::memcpy(key, it->second.data(), KEY_SIZE);
    return true;
  }

  enableArgonThreads();
  EVP_KDF *kdf = EVP_KDF_fetch(nullptr, "ARGON2ID", nullptr);
  if (!kdf)
    return false;
  EVP_KDF_CTX *kctx = EVP_KDF_CTX_new(kdf);
  EVP_KDF_free(kdf);
  if (!kctx)
    return false;

  uint32_t iter = p.t_cost, mem = p.m_cost_kib, lanes = p.lanes;
  uint32_t threads = std::min<uint32_t>(lanes, 4);
  auto build = [&](uint32_t *thr, OSSL_PARAM *out) {
    out[0] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_PASSWORD, const_cast<char *>(password_.data()),
        password_.size());
    out[1] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_SALT, const_cast<unsigned char *>(salt), SALT_SIZE);
    out[2] = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ITER, &iter);
    out[3] = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_THREADS, thr);
    out[4] = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_LANES, &lanes);
    out[5] = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_MEMCOST, &mem);
    out[6] = OSSL_PARAM_construct_end();
  };
  OSSL_PARAM params[7];
  build(&threads, params);
  bool ok = EVP_KDF_derive(kctx, key, KEY_SIZE, params) == 1;
  if (!ok) {
    // Si no hay soporte de hilos, se repite con un solo hilo (mismo resultado).
    threads = 1;
    build(&threads, params);
    ok = EVP_KDF_derive(kctx, key, KEY_SIZE, params) == 1;
  }
  EVP_KDF_CTX_free(kctx);
  if (ok)
    keyCache_[cacheKey] = std::string(reinterpret_cast<char *>(key), KEY_SIZE);
  return ok;
}

Status Session::encryptFile(const fs::path &in, const fs::path &out,
                            bool overwrite, const std::atomic<bool> *cancel) {
  if (outputBlocked(out, overwrite))
    return Status::AlreadyExists;

  std::ifstream fin(in, std::ios::binary);
  if (!fin)
    return Status::ReadError;

  if (!ensureEncryptSalt())
    return Status::CryptoError;

  unsigned char header[HEADER_SIZE] = {};
  std::memcpy(header, MAGIC, 4);
  header[4] = FORMAT_VERSION;
  header[5] = KDF_ARGON2ID;
  putU32(header + 8, params_.t_cost);
  putU32(header + 12, params_.m_cost_kib);
  putU32(header + 16, params_.lanes);
  std::memcpy(header + 20, salt_, SALT_SIZE);
  unsigned char *iv = header + 36;
  if (RAND_bytes(iv, GCM_IV_SIZE) != 1)
    return Status::CryptoError;

  SecureBuf<KEY_SIZE> key;
  if (!deriveKey(salt_, params_, key.data))
    return Status::CryptoError;

  CipherCtx ctx(EVP_CIPHER_CTX_new());
  int len = 0;
  if (!ctx ||
      EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
      EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, GCM_IV_SIZE, nullptr) != 1 ||
      EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data, iv) != 1 ||
      EVP_EncryptUpdate(ctx.get(), nullptr, &len, header, HEADER_SIZE) != 1)
    return Status::CryptoError;

  TempOutput tmp(out);
  if (!tmp.open())
    return Status::WriteError;
  if (!tmp.write(header, HEADER_SIZE))
    return Status::WriteError;

  SecureVec plain(CHUNK);
  std::vector<unsigned char> enc(CHUNK + EVP_MAX_BLOCK_LENGTH);
  while (true) {
    if (cancelled(cancel))
      return Status::Cancelled;
    fin.read(reinterpret_cast<char *>(plain.data()), CHUNK);
    std::streamsize got = fin.gcount();
    if (fin.bad())
      return Status::ReadError;
    if (got > 0) {
      if (EVP_EncryptUpdate(ctx.get(), enc.data(), &len, plain.data(), int(got)) != 1)
        return Status::CryptoError;
      if (!tmp.write(enc.data(), size_t(len)))
        return Status::WriteError;
    }
    if (fin.eof())
      break;
  }

  if (EVP_EncryptFinal_ex(ctx.get(), enc.data(), &len) != 1)
    return Status::CryptoError;
  if (len > 0 && !tmp.write(enc.data(), size_t(len)))
    return Status::WriteError;

  unsigned char tag[TAG_SIZE];
  if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag) != 1)
    return Status::CryptoError;
  if (!tmp.write(tag, TAG_SIZE))
    return Status::WriteError;

  return tmp.commit(overwrite);
}

namespace {

// Descifra el formato antiguo: [salt(16)][AES-256-CBC], clave e IV con
// PBKDF2-SHA256 (el IV era el prefijo de la clave). Sin autenticación.
Status decryptLegacy(std::ifstream &fin, uintmax_t size,
                     const std::string &password, const fs::path &out,
                     bool overwrite, const std::atomic<bool> *cancel) {
  if (size < SALT_SIZE + 16 || (size - SALT_SIZE) % 16 != 0)
    return Status::InvalidFormat;

  fin.clear();
  fin.seekg(0);
  unsigned char salt[SALT_SIZE];
  if (!readExact(fin, salt, SALT_SIZE))
    return Status::ReadError;

  SecureBuf<KEY_SIZE> key;
  SecureBuf<LEGACY_IV_SIZE> iv;
  if (PKCS5_PBKDF2_HMAC(password.data(), int(password.size()), salt, SALT_SIZE,
                        LEGACY_PBKDF2_ITER, EVP_sha256(), KEY_SIZE, key.data) != 1 ||
      PKCS5_PBKDF2_HMAC(password.data(), int(password.size()), salt, SALT_SIZE,
                        LEGACY_PBKDF2_ITER, EVP_sha256(), LEGACY_IV_SIZE, iv.data) != 1)
    return Status::CryptoError;

  CipherCtx ctx(EVP_CIPHER_CTX_new());
  if (!ctx ||
      EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_cbc(), nullptr, key.data, iv.data) != 1)
    return Status::CryptoError;

  TempOutput tmp(out);
  if (!tmp.open())
    return Status::WriteError;

  std::vector<unsigned char> buf(CHUNK);
  SecureVec plain(CHUNK + EVP_MAX_BLOCK_LENGTH);
  int len = 0;
  while (true) {
    if (cancelled(cancel))
      return Status::Cancelled;
    fin.read(reinterpret_cast<char *>(buf.data()), CHUNK);
    std::streamsize got = fin.gcount();
    if (fin.bad())
      return Status::ReadError;
    if (got > 0) {
      if (EVP_DecryptUpdate(ctx.get(), plain.data(), &len, buf.data(), int(got)) != 1)
        return Status::CryptoError;
      if (!tmp.write(plain.data(), size_t(len)))
        return Status::WriteError;
    }
    if (fin.eof())
      break;
  }
  if (EVP_DecryptFinal_ex(ctx.get(), plain.data(), &len) != 1)
    return Status::WrongPasswordOrCorrupt;
  if (len > 0 && !tmp.write(plain.data(), size_t(len)))
    return Status::WriteError;
  return tmp.commit(overwrite);
}

} // namespace

Status Session::decryptFile(const fs::path &in, const fs::path &out,
                            bool overwrite, const std::atomic<bool> *cancel,
                            bool *legacy) {
  if (legacy)
    *legacy = false;
  if (outputBlocked(out, overwrite))
    return Status::AlreadyExists;

  std::error_code ec;
  uintmax_t size = fs::file_size(in, ec);
  if (ec)
    return Status::ReadError;
  std::ifstream fin(in, std::ios::binary);
  if (!fin)
    return Status::ReadError;

  unsigned char header[HEADER_SIZE];
  bool haveHeader = size >= HEADER_SIZE + TAG_SIZE && readExact(fin, header, HEADER_SIZE);
  if (!haveHeader || std::memcmp(header, MAGIC, 4) != 0) {
    if (legacy)
      *legacy = true;
    return decryptLegacy(fin, size, password_, out, overwrite, cancel);
  }

  if (header[4] != FORMAT_VERSION || header[5] != KDF_ARGON2ID)
    return Status::InvalidFormat;
  KdfParams p;
  p.t_cost = getU32(header + 8);
  p.m_cost_kib = getU32(header + 12);
  p.lanes = getU32(header + 16);
  if (p.t_cost < 1 || p.t_cost > MAX_T_COST || p.lanes < 1 ||
      p.lanes > MAX_LANES || p.m_cost_kib < 8 * p.lanes ||
      p.m_cost_kib > MAX_M_COST_KIB)
    return Status::InvalidFormat;
  const unsigned char *salt = header + 20;
  const unsigned char *iv = header + 36;

  SecureBuf<KEY_SIZE> key;
  if (!deriveKey(salt, p, key.data))
    return Status::CryptoError;

  CipherCtx ctx(EVP_CIPHER_CTX_new());
  int len = 0;
  if (!ctx ||
      EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
      EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, GCM_IV_SIZE, nullptr) != 1 ||
      EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.data, iv) != 1 ||
      EVP_DecryptUpdate(ctx.get(), nullptr, &len, header, HEADER_SIZE) != 1)
    return Status::CryptoError;

  TempOutput tmp(out);
  if (!tmp.open())
    return Status::WriteError;

  uintmax_t remaining = size - HEADER_SIZE - TAG_SIZE;
  std::vector<unsigned char> buf(CHUNK);
  SecureVec plain(CHUNK + EVP_MAX_BLOCK_LENGTH);
  while (remaining > 0) {
    if (cancelled(cancel))
      return Status::Cancelled;
    size_t n = size_t(std::min<uintmax_t>(remaining, CHUNK));
    if (!readExact(fin, buf.data(), n))
      return Status::ReadError;
    remaining -= n;
    if (EVP_DecryptUpdate(ctx.get(), plain.data(), &len, buf.data(), int(n)) != 1)
      return Status::CryptoError;
    // Se escribe en el temporal; solo se publica si el tag es válido.
    if (!tmp.write(plain.data(), size_t(len)))
      return Status::WriteError;
  }

  unsigned char tag[TAG_SIZE];
  if (!readExact(fin, tag, TAG_SIZE))
    return Status::ReadError;
  if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, TAG_SIZE, tag) != 1)
    return Status::CryptoError;
  if (EVP_DecryptFinal_ex(ctx.get(), plain.data(), &len) != 1)
    return Status::WrongPasswordOrCorrupt;

  return tmp.commit(overwrite);
}

// ---------------------------------------------------------------------------

Summary process(const std::vector<fs::path> &targets,
                const std::string &password, Mode mode, const Options &opts,
                const ProgressFn &progress, const std::atomic<bool> *cancel) {
  Summary sum;
  Plan plan = planFiles(targets, mode);
  const size_t total = plan.jobs.size();
  size_t done = 0;

  for (auto &r : plan.skipped) {
    if (isFailure(r.status))
      ++sum.failed;
    else
      ++sum.skipped;
    if (progress)
      progress(r, done, total);
  }

  Session session(password, opts.kdf);
  for (const auto &job : plan.jobs) {
    if (cancelled(cancel)) {
      sum.cancelled = true;
      break;
    }
    FileResult r;
    r.source = job.source;
    r.output = job.output;
    if (mode == Mode::Encrypt)
      r.status = session.encryptFile(job.source, job.output, opts.overwrite, cancel);
    else
      r.status = session.decryptFile(job.source, job.output, opts.overwrite,
                                     cancel, &r.legacy);

    if (r.status == Status::Ok) {
      ++sum.ok;
      if (r.legacy) {
        // Sin autenticación no se puede garantizar que el resultado sea
        // correcto, así que nunca se borra el original en este caso.
        r.detail = "formato antiguo sin verificación de integridad: se conserva "
                   "el .enc; revisa el resultado y vuelve a cifrarlo";
      } else if (!opts.keepOriginal) {
        std::error_code ec;
        if (!fs::remove(job.source, ec))
          r.detail = "no se pudo borrar el original: " + ec.message();
      }
    } else if (r.status == Status::Cancelled) {
      sum.cancelled = true;
    } else {
      ++sum.failed;
    }
    ++done;
    if (progress)
      progress(r, done, total);
    if (sum.cancelled)
      break;
  }
  return sum;
}

} // namespace cifrado
