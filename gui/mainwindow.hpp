#pragma once

#include "cifrado.hpp"

#include <QMainWindow>
#include <atomic>

class QCheckBox;
class QLineEdit;
class QListWidget;
class QPlainTextEdit;
class QProgressBar;
class QPushButton;
class QThread;

class MainWindow : public QMainWindow {
  Q_OBJECT

public:
  explicit MainWindow(QWidget *parent = nullptr);
  ~MainWindow() override;

  void addPaths(const QStringList &paths);

protected:
  void dragEnterEvent(QDragEnterEvent *e) override;
  void dropEvent(QDropEvent *e) override;
  void closeEvent(QCloseEvent *e) override;

private:
  void start(cifrado::Mode mode);
  void setBusy(bool busy);
  void log(const QString &text, bool error = false);
  void onFileDone(const cifrado::FileResult &r, size_t done, size_t total);
  void onFinished(const cifrado::Summary &s);
  void updateButtons();

  QListWidget *list_;
  QLineEdit *password_;
  QLineEdit *confirm_;
  QCheckBox *showPassword_;
  QCheckBox *keep_;
  QCheckBox *overwrite_;
  QPushButton *addFiles_;
  QPushButton *addFolder_;
  QPushButton *remove_;
  QPushButton *clear_;
  QPushButton *encrypt_;
  QPushButton *decrypt_;
  QPushButton *cancel_;
  QProgressBar *progress_;
  QPlainTextEdit *log_;

  cifrado::Mode mode_ = cifrado::Mode::Encrypt;
  std::atomic<bool> cancelFlag_{false};
  QThread *worker_ = nullptr;
};
