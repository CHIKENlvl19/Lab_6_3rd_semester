#include <iostream>
#include <string>
#include <iomanip>
#include <libpq-fe.h>

using namespace std;

void printResult(PGresult* res) {
    int rows = PQntuples(res);
    int cols = PQnfields(res);

    const int WIDTH = 30; // ширина столбца

    // заголовки
    for (int i = 0; i < cols; i++) {
        cout << left << setw(WIDTH) << PQfname(res, i);
    }
    cout << endl;

    // разделитель
    for (int i = 0; i < cols; i++) {
        cout << string(WIDTH, '-');
    }
    cout << endl;

    // данные
    for (int i = 0; i < rows; i++) {
        for (int j = 0; j < cols; j++) {
            cout << left << setw(WIDTH) << PQgetvalue(res, i, j);
        }
        cout << endl;
    }
}

void executeQuery(PGconn* conn, const string& query) {
    PGresult* res = PQexec(conn, query.c_str());

    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        cerr << "Ошибка запроса:\n" << PQerrorMessage(conn) << endl;
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
        conn,
        query.c_str(),
        nParams,
        nullptr,
        paramValues,
        nullptr,
        nullptr,
        0
    );

    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        cerr << "Ошибка выполнения команды:\n"
             << PQerrorMessage(conn) << endl;
    } else {
        cout << "Операция выполнена успешно.\n";
    }

    PQclear(res);
}


int main() {
    const char* conninfo =
        "host=localhost "
        "port=5432 "
        "dbname=vulnerabilities_2025 "
        "user=soc_operator "
        "password=sociscool";

    PGconn* conn = PQconnectdb(conninfo);

    if (PQstatus(conn) != CONNECTION_OK) {
        cerr << "Ошибка подключения:\n" << PQerrorMessage(conn) << endl;
        PQfinish(conn);
        return 1;
    }

    cout << "Подключение к БД успешно!\n";

    int choice;
    do {
        cout << "\n===== МЕНЮ =====\n";
        cout << "1. Все уязвимости\n";
        cout << "2. Critical-уязвимости 2025 года\n";
        cout << "3. Количество уязвимостей по типам\n";
        cout << "4. Вендоры и число уязвимостей\n";
        cout << "5. Уязвимости и меры устранения\n";
        cout << "6. Продукты с SQL-инъекциями\n";
        cout << "7. Средний CVSS по уровням критичности\n";
        cout << "8. Уязвимости без мер устранения\n";
        cout << "9. Количество уязвимостей по годам\n";
        cout << "10. High и Critical уязвимости\n";
        cout << "11. Добавить уязвимость\n";
        cout << "12. Удалить уязвимость по CVE\n";
        cout << "13. Добавить меру устранения\n";
        cout << "14. Показать все меры устранения\n";
        cout << "15. Добавить продукт\n";
        cout << "0. Выход\n";
        cout << "Выбор: ";

        cin >> choice;

        switch (choice) {

        case 1:
            executeQuery(conn,
                "SELECT v.cve_id, p.name AS product, s.name AS severity, v.publish_date "
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
                "SELECT vt.name, COUNT(v.vulnerability_id) AS total "
                "FROM vulnerability_types vt "
                "LEFT JOIN vulnerabilities v ON vt.type_id = v.type_id "
                "GROUP BY vt.name "
                "ORDER BY total DESC;");
            break;

        case 4:
            executeQuery(conn,
                "SELECT ven.name, COUNT(v.vulnerability_id) AS total "
                "FROM vendors ven "
                "JOIN products p ON ven.vendor_id = p.vendor_id "
                "JOIN vulnerabilities v ON p.product_id = v.product_id "
                "GROUP BY ven.name "
                "HAVING COUNT(v.vulnerability_id) > 0 "
                "ORDER BY total DESC;");
            break;

        case 5:
            executeQuery(conn,
                "SELECT v.cve_id, m.description, m.release_date "
                "FROM vulnerabilities v "
                "JOIN mitigations m ON v.vulnerability_id = m.vulnerability_id "
                "ORDER BY m.release_date;");
            break;

        case 6:
            executeQuery(conn,
                "SELECT DISTINCT p.name AS product, ven.name AS vendor "
                "FROM vulnerabilities v "
                "JOIN products p ON v.product_id = p.product_id "
                "JOIN vendors ven ON p.vendor_id = ven.vendor_id "
                "JOIN vulnerability_types vt ON v.type_id = vt.type_id "
                "WHERE vt.name = 'SQL Injection';");
            break;

        case 7:
            executeQuery(conn,
                "SELECT name, (cvss_score_min + cvss_score_max) / 2 AS avg_cvss "
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
                "SELECT EXTRACT(YEAR FROM publish_date) AS year, COUNT(*) AS total "
                "FROM vulnerabilities "
                "GROUP BY year "
                "ORDER BY year;");
            break;

        case 10:
            executeQuery(conn,
                "SELECT v.cve_id, p.name AS product, ven.name AS vendor, s.name AS severity "
                "FROM vulnerabilities v "
                "JOIN products p ON v.product_id = p.product_id "
                "JOIN vendors ven ON p.vendor_id = ven.vendor_id "
                "JOIN severity_levels s ON v.severity_id = s.severity_id "
                "WHERE s.name IN ('High', 'Critical') "
                "ORDER BY s.name DESC;");
            break;

        case 11: {
            string cve, desc, date;
            int product_id, type_id, severity_id;

            cout << "CVE ID: ";
            cin >> cve;
            cin.ignore();

            cout << "Описание: ";
            getline(cin, desc);

            cout << "ID продукта: ";
            cin >> product_id;

            cout << "ID типа уязвимости: ";
            cin >> type_id;

            cout << "ID критичности: ";
            cin >> severity_id;

            cout << "Дата публикации (YYYY-MM-DD): ";
            cin >> date;

            string product_id_str = to_string(product_id);
            string type_id_str = to_string(type_id);
            string severity_id_str = to_string(severity_id);

            const char* params[6] = {
                cve.c_str(),
                product_id_str.c_str(),
                type_id_str.c_str(),
                severity_id_str.c_str(),
                desc.c_str(),
                date.c_str()
            };

            executeCommand(conn,
                "INSERT INTO vulnerabilities "
                "(cve_id, product_id, type_id, severity_id, description, publish_date) "
                "VALUES ($1, $2, $3, $4, $5, $6);",
                6, params
            );
            break;
        }


        case 12: {
            string cve;
            cout << "Введите CVE ID для удаления: ";
            cin >> cve;

            const char* params[1] = { cve.c_str() };

            executeCommand(conn,
                "DELETE FROM vulnerabilities WHERE cve_id = $1;",
                1, params
            );
            break;
        }

        case 13: {
            int vuln_id;
            string desc, date;

            cout << "ID уязвимости: ";
            cin >> vuln_id;
            cin.ignore();

            cout << "Описание меры: ";
            getline(cin, desc);

            cout << "Дата выпуска (YYYY-MM-DD): ";
            cin >> date;

            const char* params[3] = {
                to_string(vuln_id).c_str(),
                desc.c_str(),
                date.c_str()
            };

            executeCommand(conn,
                "INSERT INTO mitigations "
                "(vulnerability_id, description, release_date) "
                "VALUES ($1, $2, $3);",
                3, params
            );
            break;
        }

        case 14:
            executeQuery(conn,
                "SELECT m.mitigation_id, v.cve_id, m.description, m.release_date "
                "FROM mitigations m "
                "JOIN vulnerabilities v ON m.vulnerability_id = v.vulnerability_id "
                "ORDER BY m.release_date DESC;");
            break;

        case 15: {
            string name, version, vendor_name;

            cin.ignore();

            cout << "Название продукта: ";
            getline(cin, name);

            cout << "Версия продукта: ";
            getline(cin, version);

            cout << "Название вендора: ";
            getline(cin, vendor_name);

            const char* params[3] = {
                name.c_str(),
                version.c_str(),
                vendor_name.c_str()
            };

            executeCommand(conn,
                "INSERT INTO products (vendor_id, name, version) "
                "SELECT vendor_id, $1, $2 "
                "FROM vendors WHERE name = $3;",
                3, params
            );
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
