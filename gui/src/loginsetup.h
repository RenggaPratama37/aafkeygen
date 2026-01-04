#pragma once
#include <QString>

namespace LoginSetup {

// check if password is already set
bool isInitialized();

// save first time password
bool createPassword(const QString &password);

// login with password and verify
bool verifyPassword(const QString &password);

}
