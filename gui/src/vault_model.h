#pragma once
#include <QAbstractTableModel>
#include <QFileInfo>
#include <QDateTime>

struct VaultEntry {
    QString path;
    QString name;
    QString originalExt;
    qint64 size;
    QDateTime modified;
};

class VaultModel : public QAbstractTableModel
{
    Q_OBJECT
public:
    explicit VaultModel(QObject *parent = nullptr);

    int rowCount(const QModelIndex &) const override;
    int columnCount(const QModelIndex &) const override;
    QVariant data(const QModelIndex &, int role) const override;
    QVariant headerData(int, Qt::Orientation, int) const override;

    void loadVault();

    const VaultEntry &entry(int row) const;

private:
    QVector<VaultEntry> m_entries;
};
