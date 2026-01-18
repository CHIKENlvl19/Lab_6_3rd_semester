#include <iostream>
#include <string>
#include "db.h"
#include "queries.h"

using namespace std;

int main() {
    PGconn* conn = connectDB();
    if (!conn) return 1;

    int choice;
    do {
        cout << "\n    МЕНЮ    \n";
        cout << "1  - Все уязвимости\n";
        cout << "2  - Critical уязвимости 2025\n";
        cout << "3  - Количество по типам\n";
        cout << "4  - Топ-5 уязвимых продуктов\n";
        cout << "5  - Уязвимости без устранения\n";
        cout << "6  - Продукты с SQL Injection\n";
        cout << "7  - Средний CVSS\n";
        cout << "8  - Уязвимости по годам и критичности\n";
        cout << "9  - Вендоры по числу уязвимостей\n";
        cout << "10 - Уязвимости продукта (по ID)\n";

        cout << "\n--- Управление данными ---\n";
        cout << "11 - Добавить вендора\n";
        cout << "12 - Добавить продукт\n";
        cout << "13 - Добавить уязвимость\n";
        cout << "14 - Добавить меру устранения\n";
        cout << "15 - Удалить уязвимость по CVE\n";
        cout << "16 - Удалить продукт\n";

        cout << "\n0  - Выход\n> ";
        cin >> choice;

        switch (choice) {

        // SELECT

        case 1: executeQuery(conn, Queries::ALL_VULNERABILITIES); break;
        case 2: executeQuery(conn, Queries::CRITICAL_2025); break;
        case 3: executeQuery(conn, Queries::COUNT_BY_TYPE); break;
        case 4: executeQuery(conn, Queries::TOP5_PRODUCTS); break;
        case 5: executeQuery(conn, Queries::VULNS_WITHOUT_MITIGATION); break;
        case 6: executeQuery(conn, Queries::SQLI_PRODUCTS); break;
        case 7: executeQuery(conn, Queries::AVG_CVSS); break;
        case 8: executeQuery(conn, Queries::COUNT_BY_YEAR_SEVERITY); break;
        case 9: executeQuery(conn, Queries::VENDORS_BY_VULNS); break;

        case 10: {
            string productId;
            cout << "Введите ID продукта: ";
            cin >> productId;
            const char* params[] = { productId.c_str() };
            executeCommand(conn, Queries::VULNS_BY_PRODUCT, 1, params);
            break;
        }

        // INSERT / DELETE 

        case 11: {
            string name, country;
            cin.ignore();

            cout << "Название вендора: ";
            getline(cin, name);

            cout << "Страна: ";
            getline(cin, country);

            const char* params[] = {
                name.c_str(),
                country.c_str()
            };

            executeCommand(conn, Queries::Q_INSERT_VENDOR, 2, params);
            break;
        }

        case 12: {
            string product, version, vendor;
            cin.ignore();

            cout << "Название продукта: ";
            getline(cin, product);

            cout << "Версия: ";
            getline(cin, version);

            cout << "Вендор: ";
            getline(cin, vendor);

            const char* params[] = {
                product.c_str(),
                version.c_str(),
                vendor.c_str()
            };

            executeCommand(conn, Queries::Q_INSERT_PRODUCT, 3, params);
            break;
        }

        case 13: {
            string cve, desc, date;
            int productId, typeId, severityId;

            cout << "CVE ID: ";
            cin >> cve;
            cin.ignore();

            cout << "Описание: ";
            getline(cin, desc);

            cout << "ID продукта: ";
            cin >> productId;

            cout << "ID типа уязвимости: ";
            cin >> typeId;

            cout << "ID критичности: ";
            cin >> severityId;

            cout << "Дата публикации (YYYY-MM-DD): ";
            cin >> date;

            string pid = to_string(productId);
            string tid = to_string(typeId);
            string sid = to_string(severityId);

            const char* params[] = {
                cve.c_str(),
                pid.c_str(),
                tid.c_str(),
                sid.c_str(),
                desc.c_str(),
                date.c_str()
            };

            executeCommand(conn, Queries::Q_INSERT_VULNERABILITY, 6, params);
            break;
        }

        case 14: {
            int vulnId;
            string desc, date;

            cout << "ID уязвимости: ";
            cin >> vulnId;
            cin.ignore();

            cout << "Описание меры: ";
            getline(cin, desc);

            cout << "Дата выпуска (YYYY-MM-DD): ";
            cin >> date;

            string vid = to_string(vulnId);

            const char* params[] = {
                vid.c_str(),
                desc.c_str(),
                date.c_str()
            };

            executeCommand(conn, Queries::Q_INSERT_MITIGATION, 3, params);
            break;
        }

        case 15: {
            string cve;
            cout << "CVE для удаления: ";
            cin >> cve;

            const char* params[] = { cve.c_str() };
            executeCommand(conn, Queries::Q_DELETE_VULNERABILITY, 1, params);
            break;
        }

        case 16: {
            string product;
            cin.ignore();

            cout << "Название продукта для удаления: ";
            getline(cin, product);

            const char* params[] = { product.c_str() };
            executeCommand(conn, Queries::Q_DELETE_PRODUCT, 1, params);
            break;
        }

        case 0:
            cout << "Выход...\n";
            break;

        default:
            cout << "Неверный выбор!\n";
        }

    } while (choice != 0);

    disconnectDB(conn);
    return 0;
}
