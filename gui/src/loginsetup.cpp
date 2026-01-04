#include "loginsetup.h"
#include <QCryptographicHash>
#include <QFile>
#include <QDir>
#include <QRandomGenerator>

static QString configDir()
{
    return QDir::homePath() + "/.config/aafkeygen/";
}

static QString vaultFile()
{
    return configDir() + "vault.conf";
}

namespace LoginSetup {

bool isInitialized()
{
    return QFile::exists(vaultFile());
}

bool createPassword(const QString &password)
{
    QDir().mkpath(configDir());

    QByteArray salt(16, 0);
    QRandomGenerator::global()->generate(salt.begin(), salt.end());

    QByteArray hash = QCryptographicHash::hash(
        salt + password.toUtf8(),
        QCryptographicHash::Sha256
    );

    QFile f(vaultFile());
    if (!f.open(QIODevice::WriteOnly))
        return false;

    f.write(salt.toHex() + ":" + hash.toHex());
    return true;
}

bool verifyPassword(const QString &password)
{
    QFile f(vaultFile());
    if (!f.open(QIODevice::ReadOnly))
        return false;

    auto parts = f.readAll().split(':');
    if (parts.size() != 2)
        return false;

    QByteArray salt = QByteArray::fromHex(parts[0]);
    QByteArray storedHash = QByteArray::fromHex(parts[1]);

    QByteArray checkHash = QCryptographicHash::hash(
        salt + password.toUtf8(),
        QCryptographicHash::Sha256
    );

    return checkHash == storedHash;
}

}
