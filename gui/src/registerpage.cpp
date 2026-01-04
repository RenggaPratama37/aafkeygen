#include "registerpage.h"
#include "loginsetup.h"
#include "ui_registerpage.h"
#include <QMessageBox>

RegisterPage::RegisterPage(QWidget *parent)
    : QWidget(parent), ui(new Ui::RegisterPage)
{
    ui->setupUi(this);

    connect(ui->createBtn, &QPushButton::clicked,
            this, &RegisterPage::onCreateClicked);
}

RegisterPage::~RegisterPage()
{
    delete ui;
}

void RegisterPage::onCreateClicked()
{
    QString pw1 = ui->pw1Edit->text();
    QString pw2 = ui->pw2Edit->text();

    if (pw1.isEmpty() || pw2.isEmpty()) {
        QMessageBox::warning(this, "Error", "Password masih kosong");
        return;
    }

    if (pw1 != pw2) {
        QMessageBox::warning(this, "Error", "Password tidak sama");
        return;
    }

    if (!LoginSetup::createPassword(pw1)) {
        QMessageBox::critical(this, "Error", "Gagal menyimpan password");
        return;
    }

    emit registerDone();
}

