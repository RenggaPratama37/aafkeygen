#ifndef PASSWORDDIALOG_H
#define PASSWORDDIALOG_H

#include <QDialog>

namespace Ui {
class PasswordDialog;
}

class PasswordDialog : public QDialog
{
    Q_OBJECT

public:
    enum Mode {
        Encrypt,
        Decrypt
    };

    explicit PasswordDialog(Mode mode, QWidget *parent = nullptr);
    ~PasswordDialog();

    QString password() const;

private slots:
    void onOkClicked();

private:
    Ui::PasswordDialog *ui;
    Mode m_mode;
};

#endif // PASSWORDDIALOG_H
