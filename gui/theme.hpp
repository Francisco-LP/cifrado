#pragma once

#include <QColor>

class QApplication;

namespace theme {

// Colores del tema (oscuro con acento verde).
inline const QColor Accent("#2ea86b");
inline const QColor AccentHover("#36c27c");
inline const QColor AccentPressed("#248a57");
inline const QColor TextOk("#6fdc9c");
inline const QColor TextWarn("#f0c060");
inline const QColor TextError("#ff7b72");
inline const QColor TextMuted("#8b929b");

// Aplica el estilo Fusion con la paleta oscura y la hoja de estilos.
void apply(QApplication &app);

} // namespace theme
