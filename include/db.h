#pragma once
#include <string>
#include <libpq-fe.h>

PGconn* connectDB();
void disconnectDB(PGconn* conn);

void executeQuery(PGconn* conn, const std::string& query);
void executeCommand(
    PGconn* conn,
    const std::string& query,
    int nParams = 0,
    const char* const* params = nullptr
);
