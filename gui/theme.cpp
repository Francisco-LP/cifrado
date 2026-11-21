#include "theme.hpp"

#include <QApplication>
#include <QPalette>
#include <QStyleFactory>

namespace theme {

void apply(QApplication &app) {
  // Fusion respeta la paleta por completo y se ve igual en cualquier escritorio.
  app.setStyle(QStyleFactory::create("Fusion"));

  const QColor window("#1b1d21");
  const QColor base("#23262b");
  const QColor alternate("#282b31");
  const QColor button("#2c3036");
  const QColor text("#e4e6ea");
  const QColor disabled("#62676f");
  const QColor border("#3a3f46");

  QPalette p;
  p.setColor(QPalette::Window, window);
  p.setColor(QPalette::WindowText, text);
  p.setColor(QPalette::Base, base);
  p.setColor(QPalette::AlternateBase, alternate);
  p.setColor(QPalette::ToolTipBase, button);
  p.setColor(QPalette::ToolTipText, text);
  p.setColor(QPalette::Text, text);
  p.setColor(QPalette::PlaceholderText, TextMuted);
  p.setColor(QPalette::Button, button);
  p.setColor(QPalette::ButtonText, text);
  p.setColor(QPalette::BrightText, TextError);
  p.setColor(QPalette::Light, border);
  p.setColor(QPalette::Midlight, border);
  p.setColor(QPalette::Mid, border);
  p.setColor(QPalette::Dark, QColor("#141518"));
  p.setColor(QPalette::Shadow, QColor("#0c0d0f"));
  p.setColor(QPalette::Highlight, Accent);
  p.setColor(QPalette::HighlightedText, Qt::white);
  p.setColor(QPalette::Link, TextOk);
  p.setColor(QPalette::LinkVisited, Accent);
#if QT_VERSION >= QT_VERSION_CHECK(6, 6, 0)
  p.setColor(QPalette::Accent, Accent);
#endif

  for (auto role : {QPalette::WindowText, QPalette::Text, QPalette::ButtonText,
                    QPalette::HighlightedText})
    p.setColor(QPalette::Disabled, role, disabled);
  p.setColor(QPalette::Disabled, QPalette::Highlight, QColor("#2f4a3c"));
  p.setColor(QPalette::Disabled, QPalette::Base, window);
  p.setColor(QPalette::Disabled, QPalette::Button, QColor("#25282d"));

  app.setPalette(p);

  // Botones principales (Cifrar / Descifrar) rellenos de verde, campos con
  // borde verde al tener el foco y una barra de progreso más moderna.
  app.setStyleSheet(QStringLiteral(R"(
    QPushButton[primary="true"] {
      background: %1; color: white; border: none; border-radius: 5px;
      padding: 6px 18px; font-weight: bold;
    }
    QPushButton[primary="true"]:hover { background: %2; }
    QPushButton[primary="true"]:pressed { background: %3; }
    QPushButton[primary="true"]:disabled { background: #2f4a3c; color: #7d8a82; }
    QLineEdit, QListWidget, QPlainTextEdit {
      border: 1px solid #3a3f46; border-radius: 4px; padding: 3px;
    }
    QLineEdit:focus, QListWidget:focus, QPlainTextEdit:focus {
      border: 1px solid %1;
    }
    QProgressBar {
      border: 1px solid #3a3f46; border-radius: 4px; background: #23262b;
      text-align: center; min-height: 20px;
    }
    QProgressBar::chunk { background: %1; border-radius: 3px; }
    QLabel#hint { color: %4; }
  )")
                        .arg(Accent.name(), AccentHover.name(),
                             AccentPressed.name(), TextMuted.name()));
}

} // namespace theme
