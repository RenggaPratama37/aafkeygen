#ifndef VAULT_VIEW_H
#define VAULT_VIEW_H

#include <QWidget>

#include <QString>
#include <QVector>

class QLabel;
class QPushButton;
class QGridLayout;

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
    void settingsRequested();

private slots:
    void onAddFileClicked();
    void onAddFolderClicked();
    void onDecryptClicked();

private:
    void addFileEntry(const QString &path);
    QString fileForButton(QObject *senderObj) const;

private:
    Ui::vault_view *ui;
    QVector<QString> m_files;
    QGridLayout *m_grid = nullptr;
};

#endif // VAULT_VIEW_H
