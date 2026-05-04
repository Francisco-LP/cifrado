# cifrado

File encryption and decryption tool using AES-256-CBC.
Built in C++ with OpenSSL on Fedora Linux.

## Requirements

- g++ with C++17
- OpenSSL (`libssl-dev` / `openssl-devel`)

```bash
# Fedora
sudo dnf install openssl-devel
```

## Build

```bash
make
```

## Usage

```bash
./cifrado encrypt /ruta/carpeta
./cifrado decrypt /ruta/carpeta
```

You will be prompted for a password. It is never passed as a command-line argument.
```



## How it works

- AES-256-CBC via OpenSSL EVP API
- Key derived from password using PBKDF2 + random salt
- IV generated randomly per file

## License

MIT