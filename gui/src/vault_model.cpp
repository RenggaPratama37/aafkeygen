#include "vault_model.h"
#include <QDir>

VaultModel::VaultModel(QObject *parent)
    : QAbstractTableModel(parent)
{}

int VaultModel::rowCount(const QModelIndex &) const {
    return m_entries.size();
}

int VaultModel::columnCount(const QModelIndex &) const {
    return 3;
}

QVariant VaultModel::data(const QModelIndex &idx, int role) const
{
    if (!idx.isValid()) return {};

    const auto &e = m_entries[idx.row()];

    if (role == Qt::DisplayRole) {
        if (idx.column() == 0) return e.name;
        if (idx.column() == 1) return e.modified.toString(Qt::DefaultLocaleShortDate);
        if (idx.column() == 2) return e.size;
    }

    if (role == Qt::UserRole)
        return e.path;

    if (role == Qt::UserRole + 1)
        return e.originalExt;

    return {};
}

QVariant VaultModel::headerData(int s, Qt::Orientation o, int role) const
{
    if (o != Qt::Horizontal || role != Qt::DisplayRole) return {};
    if (s == 0) return "File Name";
    if (s == 1) return "Modified";
    if (s == 2) return "Size";
    return {};
}

void VaultModel::loadVault()
{
    beginResetModel();
    m_entries.clear();

    QDir dir(QDir::homePath() + "/.local/share/aafkeygen/vault/");
    for (const QFileInfo &fi : dir.entryInfoList(QDir::Files | QDir::NoDotAndDotDot)) {
        QString base = fi.completeBaseName(); // strip .aaf
        m_entries.push_back({
            fi.absoluteFilePath(),
            base,
            QFileInfo(base).suffix().toLower(),
            fi.size(),
            fi.lastModified()
        });
    }

    endResetModel();
}
