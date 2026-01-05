#ifndef SETTINGSPAGE_H
#define SETTINGSPAGE_H

#include <QWidget>

QT_BEGIN_NAMESPACE
namespace Ui { class SettingsPage; }
QT_END_NAMESPACE

class SettingsPage : public QWidget
{
    Q_OBJECT

public:
    explicit SettingsPage(QWidget *parent = nullptr);
    ~SettingsPage();

signals:
    void changePasswordRequested();
    void backRequested();

private:
    Ui::SettingsPage *ui;
};

#endif // SETTINGSPAGE_H
