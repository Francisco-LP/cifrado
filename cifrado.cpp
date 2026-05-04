/*
 * cifrado - AES-256-CBC folder encryption tool
 *
 * Encrypts and decrypts all files in a directory recursively.
 * Uses AES-256-CBC via OpenSSL EVP API.
 * Key and IV are derived from a password using PBKDF2-SHA256 with a random salt.
 *
 * Usage:
 *   ./cifrado encrypt <folder>
 *   ./cifrado decrypt <folder>
 *
 * Build:
 *   make
 *
 * Author: Francisco LP
 * License: MIT
 */

#include <filesystem>
#include <fstream>
#include <iostream>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <string>
#include <termios.h>
#include <unistd.h>
#include <vector>

namespace fs = std::filesystem;

const int KEY_SIZE  = 32; // AES-256
const int IV_SIZE   = 16; // AES block size
const int SALT_SIZE = 16;

// Lee la contraseña
std::string readPassword(const std::string &prompt) {
  std::cout << prompt << std::flush;

  termios oldt, newt;
  tcgetattr(STDIN_FILENO, &oldt);
  newt = oldt;
  newt.c_lflag &= ~ECHO;
  tcsetattr(STDIN_FILENO, TCSANOW, &newt);

  std::string password;
  std::getline(std::cin, password);

  tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
  std::cout << "\n";
  return password;
}

// Deriva la clave e IV desde contraseña + salt usando PBKDF2-SHA256
bool deriveKey(const std::string &password, const unsigned char *salt,
               unsigned char *key, unsigned char *iv) {
  return PKCS5_PBKDF2_HMAC(password.c_str(), password.size(), salt, SALT_SIZE,
                            100000, EVP_sha256(), KEY_SIZE, key) &&
         PKCS5_PBKDF2_HMAC(password.c_str(), password.size(), salt, SALT_SIZE,
                            100000, EVP_sha256(), IV_SIZE, iv);
}

bool encryptFile(const fs::path &input, const fs::path &output,
                 const std::string &password) {
  std::ifstream fin(input, std::ios::binary);
  if (!fin)
    return false;
  std::vector<unsigned char> plaintext((std::istreambuf_iterator<char>(fin)),
                                       std::istreambuf_iterator<char>());
  fin.close();

  unsigned char salt[SALT_SIZE];
  RAND_bytes(salt, SALT_SIZE);

  unsigned char key[KEY_SIZE], iv[IV_SIZE];
  if (!deriveKey(password, salt, key, iv))
    return false;

  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv);

  std::vector<unsigned char> ciphertext(plaintext.size() + EVP_MAX_BLOCK_LENGTH);
  int len = 0, total = 0;

  EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size());
  total += len;
  EVP_EncryptFinal_ex(ctx, ciphertext.data() + total, &len);
  total += len;
  EVP_CIPHER_CTX_free(ctx);

  // Formato del archivo: [salt(16)][ciphertext]
  std::ofstream fout(output, std::ios::binary);
  fout.write(reinterpret_cast<char *>(salt), SALT_SIZE);
  fout.write(reinterpret_cast<char *>(ciphertext.data()), total);
  return true;
}

bool decryptFile(const fs::path &input, const fs::path &output,
                 const std::string &password) {
  std::ifstream fin(input, std::ios::binary);
  if (!fin)
    return false;

  unsigned char salt[SALT_SIZE];
  fin.read(reinterpret_cast<char *>(salt), SALT_SIZE);

  std::vector<unsigned char> ciphertext((std::istreambuf_iterator<char>(fin)),
                                        std::istreambuf_iterator<char>());
  fin.close();

  unsigned char key[KEY_SIZE], iv[IV_SIZE];
  if (!deriveKey(password, salt, key, iv))
    return false;

  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv);

  std::vector<unsigned char> plaintext(ciphertext.size());
  int len = 0, total = 0;

  EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size());
  total += len;
  if (!EVP_DecryptFinal_ex(ctx, plaintext.data() + total, &len)) {
    EVP_CIPHER_CTX_free(ctx);
    return false;
  }
  total += len;
  EVP_CIPHER_CTX_free(ctx);

  std::ofstream fout(output, std::ios::binary);
  fout.write(reinterpret_cast<char *>(plaintext.data()), total);
  return true;
}

void processFolder(const fs::path &folder, const std::string &password,
                   bool encrypt) {
  for (auto &entry : fs::recursive_directory_iterator(folder)) {
    if (!entry.is_regular_file())
      continue;

    fs::path src = entry.path();

    if (encrypt) {
      if (src.extension() == ".enc")
        continue;
      fs::path dst = fs::path(src.string() + ".enc");
      if (encryptFile(src, dst, password)) {
        fs::remove(src);
        std::cout << "Cifrado:    " << src << "\n";
      } else {
        std::cerr << "Error:      " << src << "\n";
      }
    } else {
      if (src.extension() != ".enc")
        continue;
      fs::path dst = src.parent_path() / src.stem();
      if (decryptFile(src, dst, password)) {
        fs::remove(src);
        std::cout << "Descifrado: " << dst << "\n";
      } else {
        fs::remove(dst);
        std::cerr << "Error (contraseña incorrecta?): " << src << "\n";
      }
    }
  }
}

int main(int argc, char *argv[]) {
  if (argc != 3) {
    std::cerr << "Uso: " << argv[0] << " [encrypt|decrypt] <carpeta>\n";
    return 1;
  }

  std::string mode   = argv[1];
  fs::path    folder = argv[2];

  if (!fs::exists(folder) || !fs::is_directory(folder)) {
    std::cerr << "Error: carpeta no válida\n";
    return 1;
  }

  if (mode != "encrypt" && mode != "decrypt") {
    std::cerr << "Error: modo inválido. Usa 'encrypt' o 'decrypt'\n";
    return 1;
  }

  std::string password = readPassword("Contraseña: ");
  if (password.empty()) {
    std::cerr << "Error: contraseña vacía\n";
    return 1;
  }

  processFolder(folder, password, mode == "encrypt");
  return 0;
}