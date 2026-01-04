#include "settingspage.h"
#include "ui_settingspage.h"

SettingsPage::SettingsPage(QWidget *parent)
    : QWidget(parent),
      ui(new Ui::SettingsPage)
{
    ui->setupUi(this);

    connect(ui->btnChangePassword, &QPushButton::clicked,
            this, &SettingsPage::changePasswordRequested);
}

SettingsPage::~SettingsPage()
{
    delete ui;
}
