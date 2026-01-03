#include "vault_view.h"
#include "ui_vault_view.h"
#include "passworddialog.h"
#include <QFileDialog>
#include <QDir>
#include <QDebug>
#include <QPushButton>

vault_view::vault_view(QWidget *parent)
    : QWidget(parent)
    , ui(new Ui::vault_view)
{
    ui->setupUi(this);

    connect(ui->btn_lock, &QPushButton::clicked, this, &vault_view::lockRequested);

    connect(ui->btn_add_file, &QPushButton::clicked, this, &vault_view::onAddFileClicked);

    connect(ui->btn_add_folder, &QPushButton::clicked, this, &vault_view::onAddFolderClicked);

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
}
