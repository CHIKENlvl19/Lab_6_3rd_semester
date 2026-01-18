#include "db.h"
#include "config.h"
#include <iostream>
#include <iomanip>

using namespace std;

PGconn* connectDB() {
    string conninfo =
        string("host=") + DB_HOST +
        " port=" + DB_PORT +
        " dbname=" + DB_NAME +
        " user=" + DB_USER +
        " password=" + DB_PASS;

    PGconn* conn = PQconnectdb(conninfo.c_str());

    if (PQstatus(conn) != CONNECTION_OK) {
        cerr << "Ошибка подключения: " << PQerrorMessage(conn);
        return nullptr;
    }
    return conn;
}

void disconnectDB(PGconn* conn) {
    PQfinish(conn);
}

void executeQuery(PGconn* conn, const string& query) {
    PGresult* res = PQexec(conn, query.c_str());
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        cerr << PQerrorMessage(conn);
        PQclear(res);
        return;
    }

    int rows = PQntuples(res);
    int cols = PQnfields(res);
    const int W = 25;

    for (int i = 0; i < cols; i++)
        cout << left << setw(W) << PQfname(res, i);
    cout << endl;

    for (int i = 0; i < cols; i++)
        cout << string(W, '-');
    cout << endl;

    for (int i = 0; i < rows; i++) {
        for (int j = 0; j < cols; j++)
            cout << left << setw(W) << PQgetvalue(res, i, j);
        cout << endl;
    }

    PQclear(res);
}

void executeCommand(PGconn* conn,
                    const string& query,
                    int nParams,
                    const char* const* params) {

    PGresult* res = PQexecParams(
        conn, query.c_str(),
        nParams, nullptr,
        params, nullptr, nullptr, 0
    );

    if (PQresultStatus(res) != PGRES_COMMAND_OK)
        cerr << PQerrorMessage(conn);
    else
        cout << "Операция выполнена успешно.\n";

    PQclear(res);
}
