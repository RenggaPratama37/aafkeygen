#include "vault_view.h"
#include "ui_vault_view.h"
#include <QPushButton>

vault_view::vault_view(QWidget *parent)
    : QWidget(parent)
    , ui(new Ui::vault_view)
{
    ui->setupUi(this);

    // When lock button is clicked, notify parent to switch back to login
    connect(ui->btn_lock, &QPushButton::clicked, this, &vault_view::lockRequested);
}

vault_view::~vault_view()
{
    delete ui;
}
