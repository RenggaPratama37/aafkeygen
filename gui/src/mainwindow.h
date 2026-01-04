#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>

class QStackedWidget;
class vault_view;

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void on_unlock_clicked();  // <-- Tambahkan ini bro

    void slideTo(int index);

private:
    Ui::MainWindow *ui;
    QStackedWidget *stackedWidget = nullptr;
    vault_view *vault = nullptr;
};

#endif // MAINWINDOW_H
