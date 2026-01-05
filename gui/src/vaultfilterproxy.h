#ifndef VAULTFILTERPROXY_H
#define VAULTFILTERPROXY_H

#include <QSortFilterProxyModel>

class VaultFilterProxy : public QSortFilterProxyModel
{
    Q_OBJECT
public:
    enum Category {
        All,
        Images,
        Documents,
        Videos,
        Others
    };

    explicit VaultFilterProxy(QObject *parent = nullptr);

    void setCategory(Category c);

protected:
    bool filterAcceptsRow(int row, const QModelIndex &parent) const override;

private:
    Category m_cat = All;
};

#endif
