#include <iostream>
#include <string>
#include <iomanip>
#include <libpq-fe.h>

using namespace std;

const char* DB_HOST = "localhost";
const char* DB_PORT = "5432";
const char* DB_NAME = "vulnerabilities_2025";
const char* DB_USER = "soc_operator";
const char* DB_PASS = "sociscool";

void printResult(PGresult* res) {
    int rows = PQntuples(res);
    int cols = PQnfields(res);
    const int WIDTH = 30;

    for (int i = 0; i < cols; i++)
        cout << left << setw(WIDTH) << PQfname(res, i);
    cout << endl;

    for (int i = 0; i < cols; i++)
        cout << string(WIDTH, '-');
    cout << endl;

    for (int i = 0; i < rows; i++) {
        for (int j = 0; j < cols; j++)
            cout << left << setw(WIDTH) << PQgetvalue(res, i, j);
        cout << endl;
    }
}

void executeQuery(PGconn* conn, const string& query) {
    PGresult* res = PQexec(conn, query.c_str());
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        cerr << "Ошибка запроса:\n" << PQerrorMessage(conn);
        PQclear(res);
        return;
    }
    printResult(res);
    PQclear(res);
}

void executeCommand(PGconn* conn, const string& query,
                    int nParams = 0,
                    const char* const* paramValues = nullptr) {

    PGresult* res = PQexecParams(
        conn, query.c_str(),
        nParams, nullptr,
        paramValues, nullptr, nullptr, 0
    );

    if (PQresultStatus(res) != PGRES_COMMAND_OK)
        cerr << "Ошибка выполнения:\n" << PQerrorMessage(conn);
    else
        cout << "Операция выполнена успешно.\n";

    PQclear(res);
}

int main() {

    string conninfo =
        string("host=") + DB_HOST +
        " port=" + DB_PORT +
        " dbname=" + DB_NAME +
        " user=" + DB_USER +
        " password=" + DB_PASS;

    PGconn* conn = PQconnectdb(conninfo.c_str());

    if (PQstatus(conn) != CONNECTION_OK) {
        cerr << "Ошибка подключения:\n" << PQerrorMessage(conn);
        PQfinish(conn);
        return 1;
    }

    cout << "Подключение к БД успешно!\n";

    int choice;
    do {
        cout << "\n           МЕНЮ           \n";

        cout << "\nАНАЛИТИЧЕСКИЕ ЗАПРОСЫ\n";
        cout << " 1. Все уязвимости\n";
        cout << " 2. Critical-уязвимости 2025 года\n";
        cout << " 3. Количество уязвимостей по типам\n";
        cout << " 4. Вендоры и число уязвимостей\n";
        cout << " 5. Уязвимости и меры устранения\n";
        cout << " 6. Продукты с SQL-инъекциями\n";
        cout << " 7. Средний CVSS по уровням критичности\n";
        cout << " 8. Уязвимости без мер устранения\n";
        cout << " 9. Количество уязвимостей по годам\n";
        cout << "10. High и Critical уязвимости\n";

        cout << "\nУПРАВЛЕНИЕ ДАННЫМИ\n";
        cout << "11. Добавить уязвимость\n";
        cout << "12. Удалить уязвимость по CVE\n";
        cout << "13. Добавить меру устранения\n";
        cout << "14. Показать все меры устранения\n";
        cout << "15. Добавить продукт\n";

        cout << "\n0. Выход\n";
        cout << "Выбор: ";
        cin >> choice;

        switch (choice) {

        case 1:
            executeQuery(conn,
                "SELECT v.cve_id, p.name, s.name, v.publish_date "
                "FROM vulnerabilities v "
                "JOIN products p ON v.product_id = p.product_id "
                "JOIN severity_levels s ON v.severity_id = s.severity_id "
                "ORDER BY v.publish_date DESC;");
            break;

        case 2:
            executeQuery(conn,
                "SELECT v.cve_id, p.name, v.description "
                "FROM vulnerabilities v "
                "JOIN products p ON v.product_id = p.product_id "
                "JOIN severity_levels s ON v.severity_id = s.severity_id "
                "WHERE s.name = 'Critical' "
                "AND EXTRACT(YEAR FROM v.publish_date) = 2025;");
            break;

        case 3:
            executeQuery(conn,
                "SELECT vt.name, COUNT(*) "
                "FROM vulnerability_types vt "
                "LEFT JOIN vulnerabilities v ON vt.type_id = v.type_id "
                "GROUP BY vt.name;");
            break;

        case 4:
            executeQuery(conn,
                "SELECT ven.name, COUNT(*) "
                "FROM vendors ven "
                "JOIN products p ON ven.vendor_id = p.vendor_id "
                "JOIN vulnerabilities v ON p.product_id = v.product_id "
                "GROUP BY ven.name;");
            break;

        case 5:
            executeQuery(conn,
                "SELECT v.cve_id, m.description, m.release_date "
                "FROM vulnerabilities v "
                "JOIN mitigations m ON v.vulnerability_id = m.vulnerability_id;");
            break;

        case 6:
            executeQuery(conn,
                "SELECT DISTINCT p.name, ven.name "
                "FROM vulnerabilities v "
                "JOIN products p ON v.product_id = p.product_id "
                "JOIN vendors ven ON p.vendor_id = ven.vendor_id "
                "JOIN vulnerability_types vt ON v.type_id = vt.type_id "
                "WHERE vt.name = 'SQL Injection';");
            break;

        case 7:
            executeQuery(conn,
                "SELECT name, (cvss_score_min + cvss_score_max)/2 AS avg_cvss "
                "FROM severity_levels;");
            break;

        case 8:
            executeQuery(conn,
                "SELECT v.cve_id, v.description "
                "FROM vulnerabilities v "
                "LEFT JOIN mitigations m ON v.vulnerability_id = m.vulnerability_id "
                "WHERE m.mitigation_id IS NULL;");
            break;

        case 9:
            executeQuery(conn,
                "SELECT EXTRACT(YEAR FROM publish_date), COUNT(*) "
                "FROM vulnerabilities GROUP BY 1 ORDER BY 1;");
            break;

        case 10:
            executeQuery(conn,
                "SELECT v.cve_id, p.name, s.name "
                "FROM vulnerabilities v "
                "JOIN products p ON v.product_id = p.product_id "
                "JOIN severity_levels s ON v.severity_id = s.severity_id "
                "WHERE s.name IN ('High','Critical');");
            break;

        case 11: {
            string cve, desc, date;
            int product, type, severity;
            cin.ignore();
            cout << "CVE: "; getline(cin, cve);
            cout << "Описание: "; getline(cin, desc);
            cout << "ID продукта: "; cin >> product;
            cout << "ID типа: "; cin >> type;
            cout << "ID критичности: "; cin >> severity;
            cout << "Дата (YYYY-MM-DD): "; cin >> date;

            const char* params[] = {
                cve.c_str(),
                to_string(product).c_str(),
                to_string(type).c_str(),
                to_string(severity).c_str(),
                desc.c_str(),
                date.c_str()
            };

            executeCommand(conn,
                "INSERT INTO vulnerabilities "
                "(cve_id, product_id, type_id, severity_id, description, publish_date) "
                "VALUES ($1,$2,$3,$4,$5,$6);",
                6, params);
            break;
        }

        case 12: {
            string cve;
            cout << "CVE для удаления: ";
            cin >> cve;
            const char* p[] = { cve.c_str() };
            executeCommand(conn,
                "DELETE FROM vulnerabilities WHERE cve_id = $1;",
                1, p);
            break;
        }

        case 13: {
            int id;
            string desc, date;
            cout << "ID уязвимости: "; cin >> id;
            cin.ignore();
            cout << "Описание меры: "; getline(cin, desc);
            cout << "Дата: "; cin >> date;

            const char* p[] = {
                to_string(id).c_str(),
                desc.c_str(),
                date.c_str()
            };

            executeCommand(conn,
                "INSERT INTO mitigations "
                "(vulnerability_id, description, release_date) "
                "VALUES ($1,$2,$3);",
                3, p);
            break;
        }

        case 14:
            executeQuery(conn,
                "SELECT * FROM mitigations ORDER BY release_date DESC;");
            break;

        case 15: {
            string name, version, vendor;
            cin.ignore();
            cout << "Название продукта: "; getline(cin, name);
            cout << "Версия: "; getline(cin, version);
            cout << "Вендор: "; getline(cin, vendor);

            const char* p[] = {
                name.c_str(),
                version.c_str(),
                vendor.c_str()
            };

            executeCommand(conn,
                "INSERT INTO products (vendor_id, name, version) "
                "SELECT vendor_id, $1, $2 FROM vendors WHERE name = $3;",
                3, p);
            break;
        }

        case 0:
            cout << "Выход...\n";
            break;

        default:
            cout << "Неверный выбор!\n";
        }

    } while (choice != 0);

    PQfinish(conn);
    return 0;
}
