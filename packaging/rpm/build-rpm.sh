#!/usr/bin/env bash
# Genera los RPM (cifrado y cifrado-gui) a partir del último commit (HEAD).
# Requiere: sudo dnf install rpm-build
set -euo pipefail

root="$(git -C "$(dirname "$0")" rev-parse --show-toplevel)"
cd "$root"
version="$(sed -n 's/^Version:[[:space:]]*//p' packaging/rpm/cifrado.spec)"
topdir="$root/build-rpm"

if ! git diff --quiet HEAD; then
  echo "Aviso: hay cambios sin commit; el RPM se genera desde HEAD y no los incluye." >&2
fi

mkdir -p "$topdir"/{SOURCES,SPECS,BUILD,RPMS,SRPMS}
git archive --format=tar.gz --prefix="cifrado-$version/" \
  -o "$topdir/SOURCES/cifrado-$version.tar.gz" HEAD
rpmbuild --define "_topdir $topdir" -ba packaging/rpm/cifrado.spec

echo
echo "Paquetes generados:"
find "$topdir/RPMS" "$topdir/SRPMS" -name '*.rpm' -printf '  %p\n'
echo
echo "Instalar con:  sudo dnf install $topdir/RPMS/*/cifrado-*$version*.rpm"
