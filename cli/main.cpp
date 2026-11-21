/*
 * cifrado - interfaz de línea de comandos.
 *
 * Uso:
 *   cifrado encrypt [opciones] <ruta>...
 *   cifrado decrypt [opciones] <ruta>...
 *
 * Licencia: MIT
 */

#include "cifrado.hpp"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <csignal>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

#include <openssl/crypto.h>
#include <termios.h>
#include <unistd.h>

namespace {

std::atomic<bool> g_cancel{false};
termios g_savedTerm;
volatile sig_atomic_t g_termModified = 0;

void onSignalDuringPassword(int) {
  if (g_termModified)
    tcsetattr(STDIN_FILENO, TCSANOW, &g_savedTerm);
  const char nl[] = "\n";
  (void)!::write(STDERR_FILENO, nl, 1);
  _exit(130);
}

void onSignalDuringWork(int) { g_cancel.store(true); }

void installHandler(void (*fn)(int)) {
  struct sigaction sa {};
  sa.sa_handler = fn;
  sigemptyset(&sa.sa_mask);
  sigaction(SIGINT, &sa, nullptr);
  sigaction(SIGTERM, &sa, nullptr);
}

void secureClear(std::string &s) {
  OPENSSL_cleanse(s.data(), s.size());
  s.clear();
}

std::string readPassword(const char *prompt) {
  std::string pw;
  if (!isatty(STDIN_FILENO)) {
    // Entrada redirigida (scripts / tests): se lee una línea tal cual.
    std::getline(std::cin, pw);
    return pw;
  }
  std::cerr << prompt << std::flush;
  if (tcgetattr(STDIN_FILENO, &g_savedTerm) == 0) {
    termios t = g_savedTerm;
    t.c_lflag &= ~ECHO;
    g_termModified = 1;
    tcsetattr(STDIN_FILENO, TCSANOW, &t);
  }
  std::getline(std::cin, pw);
  if (g_termModified) {
    tcsetattr(STDIN_FILENO, TCSANOW, &g_savedTerm);
    g_termModified = 0;
  }
  std::cerr << "\n";
  return pw;
}

std::string humanSize(uintmax_t n) {
  const char *units[] = {"B", "KiB", "MiB", "GiB", "TiB"};
  double v = double(n);
  int u = 0;
  while (v >= 1024 && u < 4) {
    v /= 1024;
    ++u;
  }
  char buf[32];
  std::snprintf(buf, sizeof buf, u == 0 ? "%.0f %s" : "%.1f %s", v, units[u]);
  return buf;
}

void usage(const char *prog, std::ostream &os) {
  os << "Uso: " << prog << " <encrypt|decrypt> [opciones] <ruta>...\n"
        "\n"
        "Cifra o descifra archivos y carpetas (recursivamente) con AES-256-GCM.\n"
        "La contraseña se pide por teclado; nunca va como argumento.\n"
        "\n"
        "Opciones:\n"
        "  -k, --keep      conservar los archivos originales\n"
        "  -f, --force     sobrescribir destinos que ya existen\n"
        "  -n, --dry-run   mostrar qué se haría, sin modificar nada\n"
        "  -q, --quiet     mostrar solo errores y el resumen\n"
        "  -h, --help      mostrar esta ayuda\n"
        "  -V, --version   mostrar la versión\n"
        "\n"
        "Códigos de salida: 0 todo bien, 1 uso incorrecto, 2 hubo errores,\n"
        "130 cancelado.\n";
}

} // namespace

int main(int argc, char *argv[]) {
  using namespace cifrado;

  if (argc < 2) {
    usage(argv[0], std::cerr);
    return 1;
  }

  std::string cmd = argv[1];
  if (cmd == "-h" || cmd == "--help") {
    usage(argv[0], std::cout);
    return 0;
  }
  if (cmd == "-V" || cmd == "--version") {
    std::cout << "cifrado " << VERSION << "\n";
    return 0;
  }
  if (cmd != "encrypt" && cmd != "decrypt") {
    std::cerr << "Error: modo inválido '" << cmd << "'. Usa 'encrypt' o 'decrypt'.\n";
    return 1;
  }
  const Mode mode = cmd == "encrypt" ? Mode::Encrypt : Mode::Decrypt;

  Options opts;
  bool dryRun = false, quiet = false, endOfOpts = false;
  std::vector<fs::path> targets;
  for (int i = 2; i < argc; ++i) {
    std::string a = argv[i];
    if (!endOfOpts && a == "--") {
      endOfOpts = true;
    } else if (!endOfOpts && (a == "-k" || a == "--keep")) {
      opts.keepOriginal = true;
    } else if (!endOfOpts && (a == "-f" || a == "--force")) {
      opts.overwrite = true;
    } else if (!endOfOpts && (a == "-n" || a == "--dry-run")) {
      dryRun = true;
    } else if (!endOfOpts && (a == "-q" || a == "--quiet")) {
      quiet = true;
    } else if (!endOfOpts && (a == "-h" || a == "--help")) {
      usage(argv[0], std::cout);
      return 0;
    } else if (!endOfOpts && a.size() > 1 && a[0] == '-') {
      std::cerr << "Error: opción desconocida '" << a << "'\n";
      return 1;
    } else {
      targets.emplace_back(a);
    }
  }
  if (targets.empty()) {
    std::cerr << "Error: indica al menos un archivo o carpeta.\n";
    return 1;
  }

  if (dryRun) {
    Plan plan = planFiles(targets, mode);
    for (const auto &r : plan.skipped)
      std::cout << "Omitido:  " << r.source << " (" << r.detail << ")\n";
    for (const auto &j : plan.jobs)
      std::cout << (mode == Mode::Encrypt ? "Cifraría:    " : "Descifraría: ")
                << j.source << " -> " << j.output << "\n";
    std::cout << plan.jobs.size() << " archivo(s) se procesarían.\n";
    return 0;
  }

  // Si no hay nada que hacer, no tiene sentido pedir la contraseña.
  if (Plan plan = planFiles(targets, mode); plan.jobs.empty()) {
    for (const auto &r : plan.skipped)
      std::cerr << "Omitido: " << r.source << " (" << r.detail << ")\n";
    std::cerr << "No hay archivos que procesar.\n";
    return 2;
  }

  installHandler(onSignalDuringPassword);
  std::string password = readPassword("Contraseña: ");
  if (password.empty()) {
    std::cerr << "Error: contraseña vacía\n";
    return 1;
  }
  if (mode == Mode::Encrypt && isatty(STDIN_FILENO)) {
    std::string confirm = readPassword("Repite la contraseña: ");
    bool same = confirm == password;
    secureClear(confirm);
    if (!same) {
      secureClear(password);
      std::cerr << "Error: las contraseñas no coinciden\n";
      return 1;
    }
  }
  installHandler(onSignalDuringWork);

  if (!quiet)
    std::cerr << "Derivando clave (Argon2id)...\n";

  // Barra de progreso en stderr, solo si es una terminal.
  const bool showBar = !quiet && isatty(STDERR_FILENO);
  bool barVisible = false;
  std::chrono::steady_clock::time_point lastDraw{};
  auto clearBar = [&] {
    if (barVisible) {
      std::cerr << "\r\033[K" << std::flush;
      barVisible = false;
    }
  };
  auto bytesFn = [&](uintmax_t done, uintmax_t total) {
    if (!showBar)
      return;
    auto now = std::chrono::steady_clock::now();
    if (done < total && now - lastDraw < std::chrono::milliseconds(100))
      return;
    lastDraw = now;
    const int width = 30;
    int pct = total ? int(done * 100 / total) : 100;
    int filled = pct * width / 100;
    std::cerr << "\r\033[K[" << std::string(size_t(filled), '#')
              << std::string(size_t(width - filled), '.') << "] " << pct << "%  "
              << humanSize(done) << " / " << humanSize(total) << std::flush;
    barVisible = true;
  };

  auto progress = [&](const FileResult &r, size_t done, size_t total) {
    clearBar();
    std::string counter =
        "[" + std::to_string(done) + "/" + std::to_string(total) + "] ";
    if (r.status == Status::Ok) {
      if (!quiet)
        std::cout << counter
                  << (mode == Mode::Encrypt ? "Cifrado:    " : "Descifrado: ")
                  << r.output << "\n";
      if (!r.detail.empty())
        std::cerr << "  Aviso: " << r.detail << "\n";
    } else if (r.status == Status::Skipped) {
      if (!quiet)
        std::cerr << "Omitido: " << r.source << " (" << r.detail << ")\n";
    } else if (r.status == Status::Cancelled) {
      std::cerr << "Cancelado: " << r.source << "\n";
    } else {
      std::cerr << counter << "Error: " << r.source << ": " << statusText(r.status);
      if (!r.detail.empty())
        std::cerr << " (" << r.detail << ")";
      std::cerr << "\n";
    }
  };

  Summary s = process(targets, password, mode, opts, progress, &g_cancel, bytesFn);
  clearBar();
  secureClear(password);

  std::cerr << "\nResumen: " << s.ok << " correcto(s), " << s.failed
            << " error(es), " << s.skipped << " omitido(s)"
            << (s.cancelled ? ", CANCELADO" : "") << "\n";

  if (s.cancelled)
    return 130;
  return s.failed > 0 ? 2 : 0;
}
