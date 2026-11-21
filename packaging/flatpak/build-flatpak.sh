#!/usr/bin/env bash
# Compila e instala el Flatpak para el usuario actual.
# Requiere: sudo dnf install flatpak-builder
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(git -C "$here" rev-parse --show-toplevel)"
cd "$root"

flatpak remote-add --user --if-not-exists flathub \
  https://dl.flathub.org/repo/flathub.flatpakrepo

flatpak-builder --user --install --force-clean \
  --install-deps-from=flathub \
  --state-dir="$root/.flatpak-builder" \
  "$root/build-flatpak" "$here/io.github.Francisco_LP.Cifrado.yml"

echo
echo "Instalado. Ejecuta:  flatpak run io.github.Francisco_LP.Cifrado"
echo "CLI dentro del Flatpak:  flatpak run --command=cifrado io.github.Francisco_LP.Cifrado --help"
