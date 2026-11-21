# cifrado

Herramienta para cifrar y descifrar archivos y carpetas con **AES-256-GCM** y
derivación de clave **Argon2id**. Escrita en C++17 con OpenSSL, con dos
interfaces que comparten el mismo núcleo:

- `cifrado` — línea de comandos
- `cifrado-gui` — aplicación de escritorio (Qt 6)

Un archivo cifrado con una se puede descifrar con la otra.

## Requisitos

- g++ con C++17
- OpenSSL ≥ 3.2 (por Argon2id)
- Para la GUI: CMake y Qt 6 Widgets

```bash
# Fedora
sudo dnf install gcc-c++ openssl-devel            # CLI
sudo dnf install cmake qt6-qtbase-devel           # GUI
```

## Compilar

Solo CLI y tests (no necesita CMake):

```bash
make
make test
```

Todo, incluida la aplicación de escritorio:

```bash
cmake -S . -B build-cmake
cmake --build build-cmake -j
ctest --test-dir build-cmake
sudo cmake --install build-cmake   # instala cifrado, cifrado-gui y el acceso en el menú
```

## Paquetes

### RPM (Fedora)

```bash
sudo dnf install rpm-build        # una sola vez
make rpm                          # o ./packaging/rpm/build-rpm.sh
sudo dnf install build-rpm/RPMS/x86_64/cifrado-*.rpm
```

Se generan dos paquetes: `cifrado` (terminal) y `cifrado-gui` (escritorio).
El RPM se construye desde el último commit.

### Flatpak

```bash
sudo dnf install flatpak-builder  # una sola vez
make flatpak                      # o ./packaging/flatpak/build-flatpak.sh
flatpak run io.github.Francisco_LP.Cifrado
```

Usa el runtime KDE 6.11 de Flathub (se descarga automáticamente). El Flatpak
tiene acceso a la carpeta personal y a los discos externos (`/media`,
`/run/media`, `/mnt`), porque crea el `.enc` junto a cada archivo.

## Uso (terminal)

```bash
cifrado encrypt <archivo-o-carpeta>...
cifrado decrypt <archivo-o-carpeta>...
```

| Opción | Efecto |
|---|---|
| `-k`, `--keep` | conservar los originales |
| `-f`, `--force` | sobrescribir destinos que ya existen |
| `-n`, `--dry-run` | mostrar qué se haría sin modificar nada |
| `-q`, `--quiet` | solo errores y resumen |

La contraseña se pide por teclado (dos veces al cifrar) y nunca se pasa como
argumento. Si la entrada estándar no es una terminal, se lee una línea de ella
(útil para scripts).

Códigos de salida: `0` todo bien, `1` uso incorrecto, `2` hubo errores,
`130` cancelado (Ctrl+C).

## Uso (escritorio)

Arrastra archivos o carpetas a la ventana (o usa los botones), escribe la
contraseña y pulsa **Cifrar** o **Descifrar**. El trabajo se hace en segundo
plano con una barra de progreso por bytes y se puede cancelar.

## Cómo funciona

- **AES-256-GCM**: cifrado autenticado. Una contraseña incorrecta o cualquier
  modificación del archivo se detecta siempre.
- **Argon2id** (t=3, 64 MiB, 4 carriles) con salt aleatorio. La clave se deriva
  una vez por operación, no por archivo, y cada archivo usa un IV aleatorio
  de 96 bits.
- **Escritura segura**: el resultado se escribe en un archivo temporal, se hace
  `fsync` y solo entonces se mueve al destino. El original se borra solo si
  todo salió bien. Nunca se sobrescribe un archivo existente sin `--force`.
- Progreso por bytes en ambas interfaces (en la terminal, solo si la salida es
  una terminal y no se usa `-q`).
- Los archivos se procesan por bloques de 64 KiB (sirve para archivos de
  cualquier tamaño) y se crean con permisos `0600`.
- Los enlaces simbólicos se ignoran para no salir de la carpeta indicada.

### Formato de archivo (v1)

```
[magic "CFRD" 4][versión 1][kdf 1][reservado 2][t_cost 4][m_cost 4][lanes 4]
[salt 16][iv 12][texto cifrado ...][tag 16]
```

La cabecera de 48 bytes se autentica como dato asociado (AAD).

### Archivos de la versión 1.x

Los `.enc` creados con versiones anteriores (AES-256-CBC sin autenticación) se
pueden descifrar. Como ese formato no permite verificar el resultado, el `.enc`
original **se conserva**: comprueba el archivo descifrado y vuelve a cifrarlo
con la versión actual.

## Estructura

```
core/   núcleo de cifrado (biblioteca)
cli/    interfaz de terminal
gui/    aplicación de escritorio Qt 6
tests/  tests del núcleo
data/   .desktop, ícono y metadatos AppStream
packaging/  spec RPM y manifiesto Flatpak
```

## Licencia

MIT
