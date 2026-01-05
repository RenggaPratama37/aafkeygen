#include "settingspage.h"
#include "ui_settingspage.h"

SettingsPage::SettingsPage(QWidget *parent)
    : QWidget(parent),
      ui(new Ui::SettingsPage)
{
    ui->setupUi(this);

    connect(ui->btnChangePassword, &QPushButton::clicked,
            this, &SettingsPage::changePasswordRequested);
    connect(ui->btnBack, &QPushButton::clicked, 
            this, &SettingsPage::backRequested);
}

SettingsPage::~SettingsPage()
{
    delete ui;
}
