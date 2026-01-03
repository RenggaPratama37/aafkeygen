#ifndef VAULT_VIEW_H
#define VAULT_VIEW_H

#include <QWidget>

namespace Ui {
class vault_view;
}

class vault_view : public QWidget
{
    Q_OBJECT

public:
    explicit vault_view(QWidget *parent = nullptr);
    ~vault_view();

signals:
    void lockRequested();

private slots:
    void onAddFileClicked();
    void onAddFolderClicked();

private:
    Ui::vault_view *ui;
};

#endif // VAULT_VIEW_H
