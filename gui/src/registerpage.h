#ifndef REGISTERPAGE_H
#define REGISTERPAGE_H

#include <QWidget>

namespace Ui {
class RegisterPage;
}

class RegisterPage : public QWidget
{
    Q_OBJECT
public:
    explicit RegisterPage(QWidget *parent = nullptr);
    ~RegisterPage();

signals:
    void registerDone();

private slots:
    void onCreateClicked();

private:
    Ui::RegisterPage *ui;
};

#endif // REGISTERPAGE_H
