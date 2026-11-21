#include "mainwindow.hpp"

#include <QApplication>

int main(int argc, char *argv[]) {
  QApplication app(argc, argv);
  QApplication::setApplicationName("cifrado");
  QApplication::setApplicationVersion(cifrado::VERSION);
  QApplication::setDesktopFileName("cifrado");

  MainWindow w;
  // Permite abrir rutas desde el gestor de archivos ("Abrir con…").
  w.addPaths(QApplication::arguments().mid(1));
  w.show();
  return app.exec();
}
