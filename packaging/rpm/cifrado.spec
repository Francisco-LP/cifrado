Name:           cifrado
Version:        2.0.0
Release:        1%{?dist}
Summary:        Cifrado de archivos y carpetas con AES-256-GCM (terminal)
License:        MIT
URL:            https://github.com/Francisco-LP/cifrado
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  gcc-c++
BuildRequires:  cmake
BuildRequires:  openssl-devel >= 3.2
BuildRequires:  qt6-qtbase-devel
BuildRequires:  desktop-file-utils
BuildRequires:  appstream

%description
Cifra y descifra archivos y carpetas (recursivamente) con AES-256-GCM y
derivación de clave Argon2id. Detecta contraseñas incorrectas y archivos
modificados, escribe de forma atómica y nunca sobrescribe sin permiso.

Este paquete contiene la herramienta de terminal.

%package gui
Summary:        Cifrado de archivos y carpetas con AES-256-GCM (escritorio)

%description gui
Aplicación de escritorio (Qt 6) para cifrar y descifrar archivos y carpetas,
con arrastrar y soltar, barra de progreso y cancelación. Compatible con los
archivos de la herramienta de terminal.

%prep
%autosetup

%build
%cmake
%cmake_build

%install
%cmake_install

%check
%ctest
desktop-file-validate %{buildroot}%{_datadir}/applications/io.github.Francisco_LP.Cifrado.desktop
appstreamcli validate --no-net %{buildroot}%{_metainfodir}/io.github.Francisco_LP.Cifrado.metainfo.xml

%files
%license LICENSE
%doc README.md
%{_bindir}/cifrado

%files gui
%license LICENSE
%{_bindir}/cifrado-gui
%{_datadir}/applications/io.github.Francisco_LP.Cifrado.desktop
%{_datadir}/icons/hicolor/scalable/apps/io.github.Francisco_LP.Cifrado.svg
%{_metainfodir}/io.github.Francisco_LP.Cifrado.metainfo.xml

%changelog
* Sat Nov 21 2026 Francisco Lagos - 2.0.0-1
- AES-256-GCM con Argon2id, escritura atómica y compatibilidad con 1.x
- Aplicación de escritorio Qt 6 y progreso por bytes
