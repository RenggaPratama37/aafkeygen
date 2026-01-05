#include "vault_view.h"
#include "ui_vault_view.h"
#include "passworddialog.h"
#include <QFileDialog>
#include <QDir>
#include <QDebug>
#include <QPushButton>
#include <QLabel>
#include <QGridLayout>
#include <QMessageBox>
#include <QFile>
#include <QFileInfo>
#include <QHBoxLayout>

extern "C" {
#include <crypto.h>
}
 
vault_view::vault_view(QWidget *parent)
    : QWidget(parent)
    , ui(new Ui::vault_view)
{
    ui->setupUi(this);

    connect(ui->btn_lock, &QPushButton::clicked, this, &vault_view::lockRequested);

    connect(ui->btn_add_file, &QPushButton::clicked, this, &vault_view::onAddFileClicked);

    connect(ui->btn_add_folder, &QPushButton::clicked, this, &vault_view::onAddFolderClicked);

    connect(ui->btn_settings, &QPushButton::clicked, this, &vault_view::settingsRequested);

    // setup grid layout pointer to the layout created in UI
    QWidget *gridWidget = ui->fileScrollArea->widget();
    if (gridWidget) {
        m_grid = gridWidget->findChild<QGridLayout *>(QStringLiteral("fileGrid"));
    }

}

vault_view::~vault_view()
{
    delete ui;
}

void vault_view::onAddFileClicked()
{
    QString filePath = QFileDialog::getOpenFileName(
        this,
        tr("Select file to encrypt"),
        QDir::homePath(),
        tr("All Files (*)")
        );

    if (filePath.isEmpty()) {
        qDebug() << "No file selected";
        return;
    }

    PasswordDialog pwdDlg(PasswordDialog::Encrypt, this);
    if (pwdDlg.exec() != QDialog::Accepted) {
        qDebug();
        return;
    }

    QString password = pwdDlg.password();

    qDebug() << "Encrypt file:" << filePath;
    qDebug() << "Using password:" << password;

    // Prevent encrypting files that already look encrypted
    if (filePath.endsWith(QStringLiteral(".aaf"), Qt::CaseInsensitive)) {
        QMessageBox::warning(this, tr("Invalid selection"), tr("Selected file already has the .aaf extension."));
        return;
    }

    // Prepare output paths: final will be original + .aaf
    QString outPath = filePath + QStringLiteral(".aaf");
    if (QFile::exists(outPath)) {
        auto resp = QMessageBox::question(this, tr("Overwrite?"), tr("Encrypted file %1 already exists. Overwrite?").arg(outPath),
                                          QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
        if (resp != QMessageBox::Yes) return;
    }

    QString tmpOut = outPath + QStringLiteral(".tmp");

    int res = encrypt_file(filePath.toUtf8().constData(), tmpOut.toUtf8().constData(), password.toUtf8().constData());
    if (res != 0) {
        QMessageBox::critical(this, tr("Encryption failed"), tr("Failed to encrypt file: %1").arg(filePath));
        QFile::remove(tmpOut);
        return;
    }
    // Move temporary encrypted file into final location (outPath)
    if (!QFile::remove(outPath)) {
        // ignore failure — remove returns false if file didn't exist or couldn't be removed
    }
    if (!QFile::rename(tmpOut, outPath)) {
        QMessageBox::warning(this, tr("Warning"), tr("Could not move encrypted file into place. Encrypted file at: %1").arg(tmpOut));
        return;
    }

    // Add to history view using the encrypted file path so users can decrypt with GUI or CLI
    addFileEntry(outPath);
}



void vault_view::onAddFolderClicked()
{
    QString folderPath = QFileDialog::getExistingDirectory(
        this,
        tr("Select folder to encrypt"),
        QDir::homePath(),
        QFileDialog::ShowDirsOnly | QFileDialog::DontResolveSymlinks
        );

    if (folderPath.isEmpty()) {
        qDebug() << "No folder selected";
        return;
    }

    PasswordDialog pwdDlg(PasswordDialog::Encrypt, this);
    if (pwdDlg.exec() != QDialog::Accepted) {
        qDebug();
        return;
    }

    QString password = pwdDlg.password();

    qDebug() << "Selected folder:" << folderPath;
    qDebug() << "Using password:" << password;

    // For now we only support file encryption; recursive folder support can be added later
    QMessageBox::information(this, tr("Not implemented"), tr("Folder encryption is not implemented yet. Please add files individually."));
}

void vault_view::addFileEntry(const QString &path)
{
    if (!m_grid) return;

    int row = m_files.size() / 3; // 3 columns
    int col = m_files.size() % 3;

    QWidget *item = new QWidget(this);
    QHBoxLayout *lay = new QHBoxLayout(item);
    QLabel *lbl = new QLabel(QFileInfo(path).fileName(), item);
    QPushButton *btn = new QPushButton(tr("Decrypt"), item);
    btn->setProperty("path", path);
    connect(btn, &QPushButton::clicked, this, &vault_view::onDecryptClicked);
    lay->addWidget(lbl);
    lay->addWidget(btn);

    m_grid->addWidget(item, row, col);
    m_files.append(path);
}

QString vault_view::fileForButton(QObject *senderObj) const
{
    const QPushButton *b = qobject_cast<const QPushButton *>(senderObj);
    if (!b) return QString();
    return b->property("path").toString();
}

void vault_view::onDecryptClicked()
{
    QString path = fileForButton(sender());
    if (path.isEmpty()) return;

    PasswordDialog pwdDlg(PasswordDialog::Decrypt, this);
    if (pwdDlg.exec() != QDialog::Accepted) return;
    QString password = pwdDlg.password();

    // Only allow decrypting .aaf files
    if (!path.endsWith(QStringLiteral(".aaf"), Qt::CaseInsensitive)) {
        QMessageBox::warning(this, tr("Invalid file"), tr("Selected file is not an .aaf encrypted file."));
        return;
    }

    // Derive output path by stripping the .aaf extension
    QString outPath = path.left(path.length() - 4);
    QString tmpOut = outPath + QStringLiteral(".tmp");

    int res = decrypt_file(path.toUtf8().constData(), tmpOut.toUtf8().constData(), password.toUtf8().constData());
    if (res != 0) {
        QMessageBox::critical(this, tr("Decryption failed"), tr("Failed to decrypt file: %1").arg(path));
        QFile::remove(tmpOut);
        return;
    }

    // Move decrypted output into place (outPath)
    if (QFile::exists(outPath)) {
        auto resp = QMessageBox::question(this, tr("Overwrite?"), tr("File %1 already exists. Overwrite? ").arg(outPath),
                                          QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
        if (resp != QMessageBox::Yes) {
            QFile::remove(tmpOut);
            return;
        }
        QFile::remove(outPath);
    }
    if (!QFile::rename(tmpOut, outPath)) {
        QMessageBox::warning(this, tr("Warning"), tr("Could not move decrypted file into place. Decrypted file at: %1").arg(tmpOut));
    }
}
