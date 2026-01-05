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
#include <QTableWidget>
#include <QHeaderView>
#include <QDateTime>

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

    // Replace grid view with a table widget for file manager-like UI
    if (m_grid) {
        // remove existing placeholders in the grid and add a full-width table
        // create table
        m_table = new QTableWidget(this);
        m_table->setColumnCount(3);
        m_table->setHorizontalHeaderLabels({tr("File Name"), tr("Modified"), tr("Size")});
        m_table->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
        m_table->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
        m_table->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
        m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
        m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
        m_table->setSortingEnabled(true);
        // replace the fileGrid widget area with table
        QWidget *fileGridWidget = ui->fileScrollArea->widget();
        QLayoutItem *child;
        while ((child = m_grid->takeAt(0)) != nullptr) {
            if (child->widget()) { child->widget()->deleteLater(); }
            delete child;
        }
        m_grid->addWidget(m_table, 0, 0, 1, 3);

        connect(m_table, &QTableWidget::cellDoubleClicked, this, &vault_view::onTableDoubleClicked);
    }

    // Connect sidebar filter buttons
    connect(ui->btn_images, &QPushButton::clicked, this, &vault_view::onFilterImages);
    connect(ui->btn_documents, &QPushButton::clicked, this, &vault_view::onFilterDocuments);
    connect(ui->btn_videos, &QPushButton::clicked, this, &vault_view::onFilterVideos);
    connect(ui->btn_others, &QPushButton::clicked, this, &vault_view::onFilterOthers);
    connect(ui->btn_home, &QPushButton::clicked, this, &vault_view::onFilterAll);

    // Load existing vault entries
    loadVaultEntries();

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

    // Prepare vault directory and target paths
    QString vaultDir = QDir::homePath() + "/.local/share/aafkeygen/vault/";
    QDir().mkpath(vaultDir);
    QFile::setPermissions(vaultDir, QFile::ReadOwner | QFile::WriteOwner | QFile::ExeOwner);

    QString baseName = QFileInfo(filePath).fileName();
    QString targetName = baseName + QStringLiteral(".aaf");
    QString targetPath = vaultDir + targetName;
    if (QFile::exists(targetPath)) {
        auto resp = QMessageBox::question(this, tr("Overwrite?"), tr("Encrypted file %1 already exists in the vault. Overwrite?").arg(targetName),
                                          QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
        if (resp != QMessageBox::Yes) return;
    }

    // Create temporary file in system temp directory to avoid partial writes into vault
    QString tmpOut = QDir::temp().absoluteFilePath(targetName + QStringLiteral(".tmp"));

    int res = encrypt_file(filePath.toUtf8().constData(), tmpOut.toUtf8().constData(), password.toUtf8().constData());
    if (res != 0) {
        QMessageBox::critical(this, tr("Encryption failed"), tr("Failed to encrypt file: %1").arg(filePath));
        QFile::remove(tmpOut);
        return;
    }

    // Copy temporary encrypted file into vault (handles cross-filesystem)
    if (!QFile::remove(targetPath)) {
        // ignore
    }
    if (!QFile::copy(tmpOut, targetPath)) {
        QMessageBox::warning(this, tr("Warning"), tr("Could not move encrypted file into vault. Temp file at: %1").arg(tmpOut));
        QFile::remove(tmpOut);
        return;
    }
    QFile::remove(tmpOut);

    // Restrict permissions on vault file (owner read/write)
    QFile::setPermissions(targetPath, QFile::ReadOwner | QFile::WriteOwner);

    // Remove original file (user requested in-place semantics -> now moved to vault)
    if (!QFile::remove(filePath)) {
        QMessageBox::warning(this, tr("Warning"), tr("Could not remove original file after encryption: %1").arg(filePath));
    }

    // Add to history view using the vault path so users can decrypt with GUI or CLI
    addFileEntry(targetPath);
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
    if (!m_table) return;

    QFileInfo fi(path);
    int row = m_table->rowCount();
    m_table->insertRow(row);

    QTableWidgetItem *nameItem = new QTableWidgetItem(fi.fileName());
    nameItem->setData(Qt::UserRole, path);
    QDateTime mt = fi.lastModified();
    QTableWidgetItem *modItem = new QTableWidgetItem(mt.toString(Qt::DefaultLocaleShortDate));
    QTableWidgetItem *sizeItem = new QTableWidgetItem(QString::number(fi.size()));

    m_table->setItem(row, 0, nameItem);
    m_table->setItem(row, 1, modItem);
    m_table->setItem(row, 2, sizeItem);

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

    // Prepare decrypted output directory (Documents/aafkeygen)
    QString outDir = QDir::homePath() + "/Documents/aafkeygen/";
    QDir().mkpath(outDir);
    QFile::setPermissions(outDir, QFile::ReadOwner | QFile::WriteOwner | QFile::ExeOwner);

    // Derive output path by stripping the .aaf extension
    QString fileName = QFileInfo(path).fileName();
    QString origName = fileName;
    if (origName.endsWith(QStringLiteral(".aaf"), Qt::CaseInsensitive)) origName.chop(4);
    QString outPath = outDir + origName;
    QString tmpOut = QDir::temp().absoluteFilePath(origName + QStringLiteral(".tmp"));

    int res = decrypt_file(path.toUtf8().constData(), tmpOut.toUtf8().constData(), password.toUtf8().constData());
    if (res != 0) {
        QMessageBox::critical(this, tr("Decryption failed"), tr("Failed to decrypt file: %1").arg(path));
        QFile::remove(tmpOut);
        return;
    }

    // Move decrypted output into place (outPath) using copy to handle FS boundaries
    if (QFile::exists(outPath)) {
        auto resp = QMessageBox::question(this, tr("Overwrite?"), tr("File %1 already exists. Overwrite? ").arg(outPath),
                                          QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
        if (resp != QMessageBox::Yes) {
            QFile::remove(tmpOut);
            return;
        }
        QFile::remove(outPath);
    }
    if (!QFile::copy(tmpOut, outPath)) {
        QMessageBox::warning(this, tr("Warning"), tr("Could not move decrypted file into place. Decrypted file at: %1").arg(tmpOut));
        QFile::remove(tmpOut);
        return;
    }
    QFile::remove(tmpOut);

    // Restrict permissions on decrypted file
    QFile::setPermissions(outPath, QFile::ReadOwner | QFile::WriteOwner);

    // Remove encrypted file from vault after successful decryption
    if (!QFile::remove(path)) {
        QMessageBox::warning(this, tr("Warning"), tr("Could not remove encrypted file from vault: %1").arg(path));
    }
    // Refresh table entries
    loadVaultEntries();
}

void vault_view::loadVaultEntries()
{
    if (!m_table) return;
    m_table->clearContents();
    m_table->setRowCount(0);
    m_files.clear();

    QString vaultDir = QDir::homePath() + "/.local/share/aafkeygen/vault/";
    QDir dir(vaultDir);
    if (!dir.exists()) return;
    auto entries = dir.entryInfoList(QDir::Files | QDir::NoDotAndDotDot, QDir::Time);
    for (const QFileInfo &fi : entries) {
        addFileEntry(fi.absoluteFilePath());
    }
}

bool vault_view::matchesCategory(const QString &path, int cat) const
{
    // cat: 0=all,1=images,2=docs,3=videos,4=others
    if (cat == 0) return true;
    QString ext = QFileInfo(path).suffix().toLower();
    static const QStringList images = {"png","jpg","jpeg","gif","bmp","svg"};
    static const QStringList docs = {"pdf","doc","docx","txt","md","odt"};
    static const QStringList videos = {"mp4","mkv","avi","mov","webm"};
    if (cat == 1) return images.contains(ext);
    if (cat == 2) return docs.contains(ext);
    if (cat == 3) return videos.contains(ext);
    return true; // fallback
}

void vault_view::onTableDoubleClicked(int row, int column)
{
    QTableWidgetItem *it = m_table->item(row, 0);
    if (!it) return;
    QString path = it->data(Qt::UserRole).toString();
    if (path.isEmpty()) return;

    // Simulate decrypt button press for this path
    QPushButton *fake = new QPushButton();
    fake->setProperty("path", path);
    // call decrypt flow directly
    QString storedPath = fileForButton(fake);
    delete fake;
    if (storedPath.isEmpty()) return;

    // Reuse onDecryptClicked logic by simulating a button sender
    // We'll call the decrypt code directly here for clarity
    PasswordDialog pwdDlg(PasswordDialog::Decrypt, this);
    if (pwdDlg.exec() != QDialog::Accepted) return;
    QString password = pwdDlg.password();

    // derive output similar to onDecryptClicked
    QString fileName = QFileInfo(path).fileName();
    QString origName = fileName;
    if (origName.endsWith(QStringLiteral(".aaf"), Qt::CaseInsensitive)) origName.chop(4);
    QString outDir = QDir::homePath() + "/Documents/aafkeygen/";
    QDir().mkpath(outDir);
    QString outPath = outDir + origName;
    QString tmpOut = QDir::temp().absoluteFilePath(origName + QStringLiteral(".tmp"));

    int res = decrypt_file(path.toUtf8().constData(), tmpOut.toUtf8().constData(), password.toUtf8().constData());
    if (res != 0) {
        QMessageBox::critical(this, tr("Decryption failed"), tr("Failed to decrypt file: %1").arg(path));
        QFile::remove(tmpOut);
        return;
    }
    if (!QFile::copy(tmpOut, outPath)) {
        QMessageBox::warning(this, tr("Warning"), tr("Could not move decrypted file into place. Decrypted file at: %1").arg(tmpOut));
        QFile::remove(tmpOut);
        return;
    }
    QFile::remove(tmpOut);
    QFile::setPermissions(outPath, QFile::ReadOwner | QFile::WriteOwner);
    if (!QFile::remove(path)) {
        QMessageBox::warning(this, tr("Warning"), tr("Could not remove encrypted file from vault: %1").arg(path));
    }
    loadVaultEntries();
}

void vault_view::onFilterImages() { if (!m_table) return; /* simple reload + filter */ loadVaultEntries(); for (int r=m_table->rowCount()-1;r>=0;--r) if (!matchesCategory(m_table->item(r,0)->data(Qt::UserRole).toString(),1)) m_table->removeRow(r); }
void vault_view::onFilterDocuments() { if (!m_table) return; loadVaultEntries(); for (int r=m_table->rowCount()-1;r>=0;--r) if (!matchesCategory(m_table->item(r,0)->data(Qt::UserRole).toString(),2)) m_table->removeRow(r); }
void vault_view::onFilterVideos() { if (!m_table) return; loadVaultEntries(); for (int r=m_table->rowCount()-1;r>=0;--r) if (!matchesCategory(m_table->item(r,0)->data(Qt::UserRole).toString(),3)) m_table->removeRow(r); }
void vault_view::onFilterOthers() { if (!m_table) return; loadVaultEntries(); for (int r=m_table->rowCount()-1;r>=0;--r) if (matchesCategory(m_table->item(r,0)->data(Qt::UserRole).toString(),1) || matchesCategory(m_table->item(r,0)->data(Qt::UserRole).toString(),2) || matchesCategory(m_table->item(r,0)->data(Qt::UserRole).toString(),3)) m_table->removeRow(r); }
void vault_view::onFilterAll() { loadVaultEntries(); }
