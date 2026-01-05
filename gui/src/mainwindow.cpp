#include "mainwindow.h"
#include "./ui_mainwindow.h"
#include "vault_view.h"
#include "registerpage.h"
#include "settingspage.h"
#include "loginsetup.h"
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

    stackedWidget = new QStackedWidget(this);

    registerPage = new RegisterPage(this);
    loginPage = ui->centralwidget;
    vault = new vault_view(this);
    settings = new SettingsPage(this);

    stackedWidget->addWidget(registerPage);
    stackedWidget->addWidget(loginPage);
    stackedWidget->addWidget(vault);
    stackedWidget->addWidget(settings);

    // Set stacked widget as the new central widget
    this->setCentralWidget(stackedWidget);

    // Decide initial page based on whether password is set
    if (LoginSetup::isInitialized()) {
        stackedWidget->setCurrentWidget(loginPage);
    } else {
        stackedWidget->setCurrentWidget(registerPage);
    }

    connect(registerPage, &RegisterPage::registerDone, this, [this]() {
        // After registration, slide to login page
        int idx = stackedWidget->indexOf(loginPage);
        if (idx != -1)
            slideTo(idx);
    });

    // When vault requests lock, slide back to login page
    connect(vault, &vault_view::lockRequested, this, [this]() {
        int idx = stackedWidget->indexOf(loginPage);
        if (idx != -1)
            slideTo(idx);
    });

    connect(vault, &vault_view::settingsRequested, this, [this]() {
        int idx = stackedWidget->indexOf(settings);
        if (idx != -1)
            slideTo(idx);
    });

    connect(settings, &SettingsPage::backRequested, this, [this]() {
        int idx = stackedWidget->indexOf(vault);
        if (idx != -1)
            slideTo(idx);
    });

    // Checkbox show/hide password
    connect(ui->showpw, &QCheckBox::toggled, this, [this](bool checked){
        ui->pwform->setEchoMode(checked ? QLineEdit::Normal : QLineEdit::Password);
    });

    // Press enter to unlock
    connect(ui->pwform, &QLineEdit::returnPressed, ui->unlock, &QPushButton::click);
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::on_unlock_clicked()
{
    QString pw = ui->pwform->text();

    if (LoginSetup::verifyPassword(pw)) {
        slideTo(stackedWidget->indexOf(vault));
        ui->pwform->clear();
    } else {
        QMessageBox::warning(this,
            "Access Denied",
            "Password salah bro 😐"
        );
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
