#include "vaultfilterproxy.h"
#include <QFileInfo>

VaultFilterProxy::VaultFilterProxy(QObject *parent)
    : QSortFilterProxyModel(parent)
{
}

void VaultFilterProxy::setCategory(Category c)
{
    if (m_cat == c)
        return;

    m_cat = c;
    invalidateFilter();
}

bool VaultFilterProxy::filterAcceptsRow(int row, const QModelIndex &parent) const
{
    if (m_cat == All)
        return true;

    QModelIndex idx = sourceModel()->index(row, 0, parent);
    QString ext = sourceModel()->data(idx, Qt::UserRole + 1).toString().toLower();

    static const QStringList images = {"png","jpg","jpeg","gif","bmp","svg"};
    static const QStringList documents = {"pdf","doc","docx","txt","md","odt"};
    static const QStringList videos = {"mp4","mkv","avi","mov","webm"};

    if (m_cat == Images)
        return images.contains(ext);

    if (m_cat == Documents)
        return documents.contains(ext);

    if (m_cat == Videos)
        return videos.contains(ext);

    if (m_cat == Others)
        return !images.contains(ext)
            && !documents.contains(ext)
            && !videos.contains(ext);

    return true;
}
