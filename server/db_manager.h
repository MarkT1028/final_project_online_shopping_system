#ifndef DB_MANAGER_H
#define DB_MANAGER_H
#include <sqlite3.h>

int db_init(const char *db_file);

// return: 0=Fail, 1=User, 2=Admin
int db_validate_user(sqlite3 *db, const char *username, const char *password_hash);

#endif