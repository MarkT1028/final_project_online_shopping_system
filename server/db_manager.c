#include <stdio.h>
#include <string.h>
#include <sqlite3.h>
#include "db_manager.h"

static sqlite3 *db = NULL;

int db_init(const char *db_file) {
    char *err_msg = 0;
    int rc = sqlite3_open(db_file, &db);

    if (rc != SQLITE_OK) {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        return -1;
    }

    // Enable WAL mode for better concurrency
    sqlite3_exec(db, "PRAGMA journal_mode=WAL;", 0, 0, 0);
    
    // Set busy timeout to handle concurrent access
    sqlite3_busy_timeout(db, 5000); // 5 seconds

    // Create table if not exists
    const char *sql = "CREATE TABLE IF NOT EXISTS users("
                      "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                      "username TEXT UNIQUE,"
                      "password TEXT,"
                      "is_admin INTEGER);";
    
    rc = sqlite3_exec(db, sql, 0, 0, &err_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", err_msg);
        sqlite3_free(err_msg);
        return -1;
    }

    // Insert default users (Ignore if they exist)
    // admin:admin, user:user
    const char *insert_sql = 
        "INSERT OR IGNORE INTO users (username, password, is_admin) VALUES "
        "('admin', '8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918', 1), "
        "('user',  '04f8996da763b7a969b1028ee3007569eaf3a635486ddab211d512c85b9df8fb', 0);";
        
    sqlite3_exec(db, insert_sql, 0, 0, 0);

    return 0;
}

int db_validate_user(const char *username, const char *password_hash) {
    if (!db) return 0; // DB not initialized

    sqlite3_stmt *stmt;
    const char *sql = "SELECT is_admin FROM users WHERE username=? AND password=?";
    
    // Prepare SQL statement
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, 0) != SQLITE_OK) {
        return 0;
    }

    // Bind parameters (Avoid SQL Injection)
    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, password_hash, -1, SQLITE_STATIC);

    int result = 0; // Default fail
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        int is_admin = sqlite3_column_int(stmt, 0);
        result = is_admin ? 2 : 1; // 2 for Admin, 1 for User
    }

    sqlite3_finalize(stmt);
    return result;
}