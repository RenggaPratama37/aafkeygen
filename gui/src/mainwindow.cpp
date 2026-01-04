#include "mainwindow.h"
#include "./ui_mainwindow.h"
#include "vault_view.h"
#include <QStackedWidget>
#include <QPropertyAnimation>
#include <QParallelAnimationGroup>
#include <QPoint>
#include <QMessageBox>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    // Replace central widget with a QStackedWidget so we can switch pages
    stackedWidget = new QStackedWidget(this);
    // `ui->centralwidget` was created by setupUi; move it into the stack as page 0
    stackedWidget->addWidget(ui->centralwidget);

    // Create vault page and add as page 1
    vault = new vault_view(this);
    stackedWidget->addWidget(vault);

    // When vault requests lock, slide back to page 0 (login)
    connect(vault, &vault_view::lockRequested, this, [this]() {
        slideTo(0);
    });

    // Set stacked widget as the new central widget
    this->setCentralWidget(stackedWidget);
    // Checkbox show/hide password
    connect(ui->showpw, &QCheckBox::toggled, this, [this](bool checked){
        ui->pwform->setEchoMode(checked ? QLineEdit::Normal : QLineEdit::Password);
    });

    // Enter = tekan unlock
    connect(ui->pwform, &QLineEdit::returnPressed, ui->unlock, &QPushButton::click);
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::on_unlock_clicked()
{
    QString pw = ui->pwform->text();

    if (pw == "sudo") {
        // Switch to the vault page with a slide animation
        int idx = stackedWidget->indexOf(vault);
        if (idx != -1) slideTo(idx);
    } else {
        QMessageBox::warning(this, "Access Denied", "Password salah bro 😐");
    }
}

void MainWindow::slideTo(int index)
{
    if (!stackedWidget) return;
    if (index == stackedWidget->currentIndex()) return;

    QWidget *curr = stackedWidget->currentWidget();
    QWidget *next = stackedWidget->widget(index);
    int w = stackedWidget->width();

    // Ensure next is positioned to the right of the current widget
    next->setGeometry(curr->geometry());
    next->move(w, 0);
    next->show();

    auto *animCurr = new QPropertyAnimation(curr, "pos");
    animCurr->setDuration(300);
    animCurr->setStartValue(curr->pos());
    animCurr->setEndValue(QPoint(-w, 0));

    auto *animNext = new QPropertyAnimation(next, "pos");
    animNext->setDuration(300);
    animNext->setStartValue(QPoint(w, 0));
    animNext->setEndValue(QPoint(0, 0));

    auto *group = new QParallelAnimationGroup(this);
    group->addAnimation(animCurr);
    group->addAnimation(animNext);

    connect(group, &QParallelAnimationGroup::finished, this, [=]() {
        stackedWidget->setCurrentWidget(next);
        curr->hide();
        curr->move(0,0);
        group->deleteLater();
    });

    group->start();
}
