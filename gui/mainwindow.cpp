#include "mainwindow.hpp"

#include <QCheckBox>
#include <QCloseEvent>
#include <QDir>
#include <QDragEnterEvent>
#include <QDropEvent>
#include <QFileDialog>
#include <QFileInfo>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QMessageBox>
#include <QMimeData>
#include <QPlainTextEdit>
#include <QProgressBar>
#include <QPushButton>
#include <QThread>
#include <QVBoxLayout>

#include <openssl/crypto.h>

using cifrado::FileResult;
using cifrado::Mode;
using cifrado::Status;
using cifrado::Summary;

namespace {

QString toQ(const cifrado::fs::path &p) { return QString::fromStdString(p.string()); }

void wipe(QLineEdit *e) {
  // QString no permite borrar su memoria de forma garantizada; al menos se
  // sobrescribe el contenido antes de vaciar el campo.
  e->setText(QString(e->text().size(), QChar('\0')));
  e->clear();
}

} // namespace

MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent) {
  setWindowTitle(QStringLiteral("Cifrado %1").arg(cifrado::VERSION));
  setWindowIcon(QIcon::fromTheme("security-high"));
  setAcceptDrops(true);
  resize(640, 620);

  auto *central = new QWidget(this);
  auto *root = new QVBoxLayout(central);

  auto *hint = new QLabel(tr("Arrastra archivos o carpetas aquí, o usa los botones."));
  hint->setStyleSheet("color: palette(mid);");
  root->addWidget(hint);

  list_ = new QListWidget;
  list_->setSelectionMode(QAbstractItemView::ExtendedSelection);
  list_->setAlternatingRowColors(true);
  root->addWidget(list_, 1);

  auto *listButtons = new QHBoxLayout;
  addFiles_ = new QPushButton(QIcon::fromTheme("document-open"), tr("Añadir archivos…"));
  addFolder_ = new QPushButton(QIcon::fromTheme("folder-open"), tr("Añadir carpeta…"));
  remove_ = new QPushButton(QIcon::fromTheme("list-remove"), tr("Quitar"));
  clear_ = new QPushButton(QIcon::fromTheme("edit-clear"), tr("Limpiar"));
  for (auto *b : {addFiles_, addFolder_, remove_, clear_})
    listButtons->addWidget(b);
  listButtons->addStretch();
  root->addLayout(listButtons);

  auto *form = new QFormLayout;
  password_ = new QLineEdit;
  password_->setEchoMode(QLineEdit::Password);
  confirm_ = new QLineEdit;
  confirm_->setEchoMode(QLineEdit::Password);
  confirm_->setPlaceholderText(tr("solo necesaria para cifrar"));
  showPassword_ = new QCheckBox(tr("Mostrar contraseña"));
  form->addRow(tr("Contraseña:"), password_);
  form->addRow(tr("Confirmar:"), confirm_);
  form->addRow(QString(), showPassword_);
  root->addLayout(form);

  keep_ = new QCheckBox(tr("Conservar los archivos originales"));
  overwrite_ = new QCheckBox(tr("Sobrescribir archivos de destino que ya existan"));
  root->addWidget(keep_);
  root->addWidget(overwrite_);

  auto *actions = new QHBoxLayout;
  encrypt_ = new QPushButton(QIcon::fromTheme("security-high"), tr("Cifrar"));
  decrypt_ = new QPushButton(QIcon::fromTheme("security-low"), tr("Descifrar"));
  cancel_ = new QPushButton(QIcon::fromTheme("process-stop"), tr("Cancelar"));
  encrypt_->setDefault(true);
  actions->addWidget(encrypt_);
  actions->addWidget(decrypt_);
  actions->addStretch();
  actions->addWidget(cancel_);
  root->addLayout(actions);

  progress_ = new QProgressBar;
  progress_->setRange(0, 1);
  progress_->setValue(0);
  progress_->setFormat(tr("Listo"));
  progress_->setTextVisible(true);
  root->addWidget(progress_);

  log_ = new QPlainTextEdit;
  log_->setReadOnly(true);
  log_->setMaximumBlockCount(5000);
  log_->setPlaceholderText(tr("Aquí aparecerá el registro de operaciones."));
  root->addWidget(log_, 1);

  setCentralWidget(central);

  connect(addFiles_, &QPushButton::clicked, this, [this] {
    addPaths(QFileDialog::getOpenFileNames(this, tr("Elegir archivos"), QDir::homePath()));
  });
  connect(addFolder_, &QPushButton::clicked, this, [this] {
    QString d = QFileDialog::getExistingDirectory(this, tr("Elegir carpeta"), QDir::homePath());
    if (!d.isEmpty())
      addPaths({d});
  });
  connect(remove_, &QPushButton::clicked, this, [this] {
    qDeleteAll(list_->selectedItems());
    updateButtons();
  });
  connect(clear_, &QPushButton::clicked, this, [this] {
    list_->clear();
    updateButtons();
  });
  connect(list_, &QListWidget::itemSelectionChanged, this, &MainWindow::updateButtons);
  connect(password_, &QLineEdit::textChanged, this, &MainWindow::updateButtons);
  connect(showPassword_, &QCheckBox::toggled, this, [this](bool on) {
    auto m = on ? QLineEdit::Normal : QLineEdit::Password;
    password_->setEchoMode(m);
    confirm_->setEchoMode(m);
  });
  connect(encrypt_, &QPushButton::clicked, this, [this] { start(Mode::Encrypt); });
  connect(decrypt_, &QPushButton::clicked, this, [this] { start(Mode::Decrypt); });
  connect(cancel_, &QPushButton::clicked, this, [this] {
    cancelFlag_ = true;
    cancel_->setEnabled(false);
    log(tr("Cancelando… (se termina el bloque actual sin dejar archivos a medias)"));
  });

  setBusy(false);
}

MainWindow::~MainWindow() {
  if (worker_) {
    cancelFlag_ = true;
    worker_->wait();
  }
}

void MainWindow::addPaths(const QStringList &paths) {
  for (const QString &p : paths) {
    if (p.isEmpty())
      continue;
    QString abs = QFileInfo(p).absoluteFilePath();
    if (!list_->findItems(abs, Qt::MatchExactly).isEmpty())
      continue;
    auto *item = new QListWidgetItem(
        QIcon::fromTheme(QFileInfo(abs).isDir() ? "folder" : "text-x-generic"), abs);
    list_->addItem(item);
  }
  updateButtons();
}

void MainWindow::dragEnterEvent(QDragEnterEvent *e) {
  if (!worker_ && e->mimeData()->hasUrls())
    e->acceptProposedAction();
}

void MainWindow::dropEvent(QDropEvent *e) {
  QStringList paths;
  for (const QUrl &u : e->mimeData()->urls())
    if (u.isLocalFile())
      paths << u.toLocalFile();
  addPaths(paths);
  e->acceptProposedAction();
}

void MainWindow::closeEvent(QCloseEvent *e) {
  if (worker_) {
    auto answer = QMessageBox::question(
        this, tr("Operación en curso"),
        tr("Hay una operación en curso. ¿Cancelarla y salir?\n"
           "Los archivos ya procesados quedan como están; el actual se descarta."));
    if (answer != QMessageBox::Yes) {
      e->ignore();
      return;
    }
    cancelFlag_ = true;
    worker_->wait();
  }
  e->accept();
}

void MainWindow::updateButtons() {
  bool busy = worker_ != nullptr;
  bool haveItems = list_->count() > 0;
  bool havePw = !password_->text().isEmpty();
  encrypt_->setEnabled(!busy && haveItems && havePw);
  decrypt_->setEnabled(!busy && haveItems && havePw);
  remove_->setEnabled(!busy && !list_->selectedItems().isEmpty());
  clear_->setEnabled(!busy && haveItems);
}

void MainWindow::setBusy(bool busy) {
  for (QWidget *w : std::initializer_list<QWidget *>{
           list_, addFiles_, addFolder_, password_, confirm_, showPassword_,
           keep_, overwrite_})
    w->setEnabled(!busy);
  cancel_->setEnabled(busy);
  setAcceptDrops(!busy);
  updateButtons();
}

void MainWindow::log(const QString &text, bool error) {
  if (error)
    log_->appendHtml(QStringLiteral("<span style='color:#c0392b'>%1</span>")
                         .arg(text.toHtmlEscaped()));
  else
    log_->appendPlainText(text);
}

void MainWindow::start(Mode mode) {
  if (worker_ || list_->count() == 0)
    return;

  const QString pw = password_->text();
  if (pw.isEmpty())
    return;

  if (mode == Mode::Encrypt) {
    if (confirm_->text() != pw) {
      QMessageBox::warning(this, tr("Contraseñas distintas"),
                           tr("La contraseña y su confirmación no coinciden."));
      confirm_->setFocus();
      return;
    }
    if (pw.size() < 8) {
      auto a = QMessageBox::question(
          this, tr("Contraseña corta"),
          tr("La contraseña tiene menos de 8 caracteres y sería fácil de adivinar.\n"
             "¿Continuar de todos modos?"));
      if (a != QMessageBox::Yes)
        return;
    }
  }

  std::vector<cifrado::fs::path> targets;
  for (int i = 0; i < list_->count(); ++i)
    targets.emplace_back(list_->item(i)->text().toStdString());

  cifrado::Plan plan = cifrado::planFiles(targets, mode);
  if (plan.jobs.empty()) {
    QMessageBox::information(
        this, tr("Nada que hacer"),
        mode == Mode::Encrypt
            ? tr("No hay archivos sin cifrar en la selección.")
            : tr("No hay archivos .enc en la selección."));
    return;
  }

  if (mode == Mode::Encrypt && !keep_->isChecked()) {
    auto a = QMessageBox::question(
        this, tr("Confirmar cifrado"),
        tr("Se cifrarán %n archivo(s) y se borrarán los originales.\n"
           "Si olvidas la contraseña no podrás recuperarlos.\n\n¿Continuar?",
           nullptr, int(plan.jobs.size())));
    if (a != QMessageBox::Yes)
      return;
  }

  cifrado::Options opts;
  opts.keepOriginal = keep_->isChecked();
  opts.overwrite = overwrite_->isChecked();

  mode_ = mode;
  cancelFlag_ = false;
  log_->clear();
  log(mode == Mode::Encrypt ? tr("Cifrando %n archivo(s)…", nullptr, int(plan.jobs.size()))
                            : tr("Descifrando %n archivo(s)…", nullptr, int(plan.jobs.size())));
  progress_->setRange(0, 0); // indeterminado mientras se deriva la clave
  progress_->setFormat(tr("Derivando clave…"));

  std::string password = pw.toStdString();
  wipe(password_);
  wipe(confirm_);

  worker_ = QThread::create([this, targets, password, mode, opts]() mutable {
    auto progress = [this](const FileResult &r, size_t done, size_t total) {
      QMetaObject::invokeMethod(
          this, [this, r, done, total] { onFileDone(r, done, total); },
          Qt::QueuedConnection);
    };
    Summary s = cifrado::process(targets, password, mode, opts, progress, &cancelFlag_);
    OPENSSL_cleanse(password.data(), password.size());
    QMetaObject::invokeMethod(this, [this, s] { onFinished(s); }, Qt::QueuedConnection);
  });
  connect(worker_, &QThread::finished, worker_, &QObject::deleteLater);
  setBusy(true);
  worker_->start();
}

void MainWindow::onFileDone(const FileResult &r, size_t done, size_t total) {
  progress_->setRange(0, int(total));
  progress_->setValue(int(done));
  progress_->setFormat(QStringLiteral("%v / %m"));

  switch (r.status) {
  case Status::Ok:
    log((mode_ == Mode::Encrypt ? tr("✔ Cifrado: %1") : tr("✔ Descifrado: %1"))
            .arg(toQ(r.output)));
    if (!r.detail.empty())
      log(tr("   Aviso: %1").arg(QString::fromStdString(r.detail)), true);
    break;
  case Status::Skipped:
    log(tr("– Omitido: %1 (%2)").arg(toQ(r.source), QString::fromStdString(r.detail)));
    break;
  case Status::Cancelled:
    log(tr("✖ Cancelado: %1").arg(toQ(r.source)), true);
    break;
  default: {
    QString msg = tr("✖ Error: %1: %2")
                      .arg(toQ(r.source), QString::fromStdString(cifrado::statusText(r.status)));
    if (!r.detail.empty())
      msg += " (" + QString::fromStdString(r.detail) + ")";
    log(msg, true);
  }
  }
}

void MainWindow::onFinished(const Summary &s) {
  worker_ = nullptr; // se libera solo con deleteLater
  setBusy(false);
  if (progress_->maximum() == 0)
    progress_->setRange(0, 1);

  QString summary = tr("%1 correcto(s), %2 error(es), %3 omitido(s)")
                        .arg(s.ok).arg(s.failed).arg(s.skipped);
  if (s.cancelled)
    summary += tr(" — cancelado");
  log(QString());
  log(tr("Resumen: %1").arg(summary), s.failed > 0);
  progress_->setFormat(s.cancelled ? tr("Cancelado") : tr("Terminado"));

  if (s.failed > 0)
    QMessageBox::warning(this, tr("Terminado con errores"),
                         tr("%1\n\nRevisa el registro para ver los detalles.").arg(summary));

  // Las rutas cambiaron de nombre (.enc), así que la lista ya no es válida.
  if (!s.cancelled && s.failed == 0)
    list_->clear();
  updateButtons();
}
