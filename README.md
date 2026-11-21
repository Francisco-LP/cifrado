# cifrado

Herramienta para cifrar y descifrar archivos y carpetas con **AES-256-GCM** y
derivación de clave **Argon2id**. Está escrita en C++17 con OpenSSL y tiene dos
versiones que comparten el mismo núcleo de cifrado:

- `cifrado`: para usar desde la terminal.
- `cifrado-gui`: aplicación de escritorio con ventana (Qt 6).

Un archivo cifrado con una versión se puede descifrar con la otra.

## Requisitos

- Compilador g++ con soporte para C++17.
- OpenSSL 3.2 o superior (necesario para Argon2id).
- Para la aplicación de escritorio: CMake y Qt 6.

```bash
# Fedora
sudo dnf install gcc-c++ openssl-devel            # versión de terminal
sudo dnf install cmake qt6-qtbase-devel           # aplicación de escritorio
```

## Compilación

Solo la versión de terminal y las pruebas (no necesita CMake):

```bash
make
make test
```

Todo, incluida la aplicación de escritorio:

```bash
cmake -S . -B build-cmake
cmake --build build-cmake -j
ctest --test-dir build-cmake
sudo cmake --install build-cmake   # instala ambas versiones y el acceso en el menú
```

## Paquetes de instalación

### RPM (Fedora)

```bash
sudo dnf install rpm-build        # solo la primera vez
make rpm                          # o bien ./packaging/rpm/build-rpm.sh
sudo dnf install build-rpm/RPMS/x86_64/cifrado-*.rpm
```

Se generan dos paquetes: `cifrado` (terminal) y `cifrado-gui` (escritorio).
El paquete se construye a partir del último commit, así que los cambios que no
estén confirmados no se incluyen.

### Flatpak

```bash
sudo dnf install flatpak-builder  # solo la primera vez
make flatpak                      # o bien ./packaging/flatpak/build-flatpak.sh
flatpak run io.github.Francisco_LP.Cifrado
```

Usa el entorno de ejecución KDE 6.11 de Flathub, que se descarga
automáticamente. La aplicación tiene acceso a la carpeta personal y a los
discos externos (`/media`, `/run/media` y `/mnt`), porque guarda cada `.enc`
junto al archivo original.

## Uso desde la terminal

```bash
cifrado encrypt <archivo-o-carpeta>...   # cifrar
cifrado decrypt <archivo-o-carpeta>...   # descifrar
```

| Opción | Efecto |
|---|---|
| `-k`, `--keep` | conserva los archivos originales |
| `-f`, `--force` | sobrescribe los archivos de destino que ya existan |
| `-n`, `--dry-run` | muestra qué se haría, sin modificar nada |
| `-q`, `--quiet` | muestra solo los errores y el resumen |
| `-h`, `--help` | muestra la ayuda |
| `-V`, `--version` | muestra la versión |

La contraseña se pide por teclado (dos veces al cifrar) y nunca se escribe en
la línea de comandos. Si la entrada no viene de una terminal, por ejemplo desde
un script, se lee una línea de la entrada estándar.

Códigos de salida: `0` si todo salió bien, `1` si el comando se usó mal, `2`
si hubo errores con algún archivo y `130` si se canceló con Ctrl+C.

## Uso de la aplicación de escritorio

Arrastra archivos o carpetas a la ventana (o usa los botones para elegirlos),
escribe la contraseña y pulsa **Cifrar** o **Descifrar**. El trabajo se hace en
segundo plano, con una barra que muestra el avance en bytes, y se puede
cancelar en cualquier momento.

## Cómo funciona

- **AES-256-GCM**: cifrado autenticado. Siempre detecta una contraseña
  incorrecta o un archivo que fue modificado.
- **Argon2id** (3 pasadas, 64 MiB de memoria, 4 carriles) con una sal
  aleatoria. La clave se calcula una sola vez por operación, no una vez por
  archivo, y cada archivo usa su propio vector de inicialización (IV) aleatorio
  de 96 bits.
- **Escritura segura**: el resultado se escribe primero en un archivo temporal,
  se fuerza su guardado en disco (`fsync`) y solo entonces se mueve a su nombre
  final. El original se borra únicamente si todo salió bien, y nunca se
  sobrescribe un archivo existente sin `--force`.
- **Progreso por bytes** en ambas versiones. En la terminal solo se muestra si
  la salida es una terminal y no se usa `-q`.
- Los archivos se procesan en bloques de 64 KiB, así que funciona con archivos
  de cualquier tamaño. Los archivos resultantes se crean con permisos `0600`
  (solo el dueño puede leerlos).
- Los enlaces simbólicos se ignoran, para no modificar archivos fuera de la
  carpeta indicada.

### Formato del archivo cifrado (versión 1)

```
[firma "CFRD" 4][versión 1][kdf 1][reservado 2][t_cost 4][m_cost 4][lanes 4]
[sal 16][iv 12][contenido cifrado ...][etiqueta de autenticación 16]
```

Los números indican el tamaño de cada campo en bytes. La cabecera (48 bytes)
también queda protegida por la etiqueta de autenticación, así que cualquier
cambio en ella se detecta.

### Archivos de la versión 1.x

Los `.enc` creados con versiones anteriores (AES-256-CBC sin autenticación) se
pueden descifrar. Como ese formato no permite comprobar que el resultado sea
correcto, el `.enc` original **se conserva**: revisa el archivo descifrado y
vuelve a cifrarlo con la versión actual.

## Estructura del proyecto

```
core/       núcleo de cifrado (biblioteca compartida por ambas versiones)
cli/        versión de terminal
gui/        aplicación de escritorio (Qt 6)
tests/      pruebas del núcleo
data/       acceso directo (.desktop), ícono y metadatos para tiendas de apps
packaging/  archivos para generar los paquetes RPM y Flatpak
```

## Licencia

MIT. Consulta el archivo [LICENSE](LICENSE).
