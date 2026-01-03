#include "passworddialog.h"
#include "ui_passworddialog.h"

PasswordDialog::PasswordDialog(Mode mode, QWidget *parent)
    : QDialog(parent)
    , ui(new Ui::PasswordDialog)
    , m_mode(mode)
{
    ui->setupUi(this);

    connect(ui->btn_ok, &QPushButton::clicked,
            this, &PasswordDialog::onOkClicked);
    connect(ui->btn_cancel, &QPushButton::clicked,
            this, &QDialog::reject);

    if (m_mode == Decrypt) {
        // Decrypt cuma butuh 1 password
        ui->confirmEdit->hide();
        ui->label->setText("Enter password:");
    } else {
        ui->confirmEdit->show();
        ui->label->setText("Create password:");
    }
}

PasswordDialog::~PasswordDialog()
{
    delete ui;
}

QString PasswordDialog::password() const
{
    return ui->passwordEdit->text();
}

void PasswordDialog::onOkClicked()
{
    const QString pwd = ui->passwordEdit->text();

    if (pwd.isEmpty()) {
        ui->errorLabel->setText("Password cannot be empty");
        return;
    }

    if (m_mode == Encrypt) {
        if (pwd != ui->confirmEdit->text()) {
            ui->errorLabel->setText("Passwords do not match");
            return;
        }
    }

    accept();
}
