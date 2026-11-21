/*
 * cifrado - núcleo de cifrado compartido por la CLI y la GUI.
 *
 * Formato v1 (todos los enteros en little-endian):
 *
 *   offset  tamaño  campo
 *   0       4       magic "CFRD"
 *   4       1       versión (1)
 *   5       1       KDF (1 = Argon2id)
 *   6       2       reservado (0)
 *   8       4       Argon2 t_cost (iteraciones)
 *   12      4       Argon2 m_cost (KiB)
 *   16      4       Argon2 lanes
 *   20      16      salt
 *   36      12      IV / nonce de AES-GCM
 *   48      n       texto cifrado (AES-256-GCM)
 *   48+n    16      tag de autenticación
 *
 * La cabecera completa (48 bytes) se autentica como AAD, así que cualquier
 * modificación de la cabecera o del contenido se detecta al descifrar.
 *
 * También se pueden descifrar los archivos del formato antiguo (v0:
 * salt + AES-256-CBC con PBKDF2), pero ese formato no tiene autenticación.
 *
 * Licencia: MIT
 */
#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <map>
#include <string>
#include <vector>

namespace cifrado {

namespace fs = std::filesystem;

inline constexpr const char *VERSION = "2.0.0";
inline constexpr const char *ENC_EXT = ".enc";

enum class Mode { Encrypt, Decrypt };

// Parámetros de Argon2id (RFC 9106, segunda opción recomendada).
struct KdfParams {
  uint32_t t_cost = 3;
  uint32_t m_cost_kib = 64 * 1024; // 64 MiB
  uint32_t lanes = 4;
};

struct Options {
  bool keepOriginal = false; // no borrar el archivo de origen
  bool overwrite = false;    // sobrescribir destinos que ya existen
  KdfParams kdf;             // solo se usa al cifrar
};

enum class Status {
  Ok,
  Skipped,
  NotFound,
  AlreadyExists,
  ReadError,
  WriteError,
  WrongPasswordOrCorrupt,
  InvalidFormat,
  CryptoError,
  Cancelled,
};

struct FileResult {
  fs::path source;
  fs::path output;
  Status status = Status::Ok;
  bool legacy = false;  // se descifró con el formato antiguo (sin autenticación)
  std::string detail;   // información adicional para el usuario
};

struct Summary {
  size_t ok = 0;
  size_t failed = 0;
  size_t skipped = 0;
  bool cancelled = false;
};

struct Job {
  fs::path source;
  fs::path output;
  uintmax_t size = 0; // tamaño del archivo de origen en bytes
};

struct Plan {
  std::vector<Job> jobs;
  std::vector<FileResult> skipped; // rutas que no se procesarán, con el motivo
  uintmax_t totalBytes = 0;
};

// Texto legible (en español) para un estado.
std::string statusText(Status s);

bool isFailure(Status s);

// Devuelve la ruta de destino para un archivo según el modo.
fs::path outputPathFor(const fs::path &source, Mode mode);

// Calcula qué archivos se procesarán. Acepta archivos y carpetas (recursivo).
// Los enlaces simbólicos se ignoran para no salir de la carpeta indicada.
Plan planFiles(const std::vector<fs::path> &targets, Mode mode);

// Sesión de trabajo: guarda la contraseña y cachea las claves derivadas, de
// modo que Argon2 se ejecuta una sola vez por salt (y no una vez por archivo).
class Session {
public:
  Session(std::string password, KdfParams params = {});
  ~Session();
  Session(const Session &) = delete;
  Session &operator=(const Session &) = delete;

  // Escribe primero en un archivo temporal y solo lo mueve al destino si todo
  // salió bien. Nunca modifica ni borra `in`.
  Status encryptFile(const fs::path &in, const fs::path &out, bool overwrite,
                     const std::atomic<bool> *cancel = nullptr);

  // Igual que encryptFile. `legacy` indica si el archivo era del formato antiguo.
  Status decryptFile(const fs::path &in, const fs::path &out, bool overwrite,
                     const std::atomic<bool> *cancel = nullptr,
                     bool *legacy = nullptr);

  // Se llama tras cada bloque leído con la cantidad de bytes de ese bloque.
  std::function<void(uintmax_t bytes)> onBytes;

private:
  bool deriveKey(const unsigned char *salt, const KdfParams &p,
                 unsigned char *key);
  bool ensureEncryptSalt();

  std::string password_;
  KdfParams params_;
  bool haveSalt_ = false;
  unsigned char salt_[16] = {};
  std::map<std::string, std::string> keyCache_;
};

using ProgressFn =
    std::function<void(const FileResult &result, size_t done, size_t total)>;

// Progreso global en bytes (suma de todos los archivos). Se llama a menudo
// (cada 64 KiB): quien lo reciba debe limitar cuánto actualiza la interfaz.
using BytesFn = std::function<void(uintmax_t done, uintmax_t total)>;

// Procesa todas las rutas. Llama a `progress` después de cada archivo y a
// `bytes` a medida que avanza dentro de cada archivo.
// Si `cancel` pasa a true, se detiene al terminar el bloque actual sin dejar
// archivos a medias.
Summary process(const std::vector<fs::path> &targets,
                const std::string &password, Mode mode, const Options &opts,
                const ProgressFn &progress = {},
                const std::atomic<bool> *cancel = nullptr,
                const BytesFn &bytes = {});

} // namespace cifrado
