#pragma once
#include <string>

namespace Queries {

    // 1–10 НОРМАЛЬНЫЕ ЗАПРОСЫ

    const std::string ALL_VULNERABILITIES =
        "SELECT v.cve_id, p.name AS product, ven.name AS vendor, "
        "s.name AS severity, v.publish_date "
        "FROM vulnerabilities v "
        "JOIN products p ON v.product_id = p.product_id "
        "JOIN vendors ven ON p.vendor_id = ven.vendor_id "
        "JOIN severity_levels s ON v.severity_id = s.severity_id "
        "ORDER BY v.publish_date DESC;";

    const std::string CRITICAL_2025 =
        "SELECT v.cve_id, v.description "
        "FROM vulnerabilities v "
        "JOIN severity_levels s ON v.severity_id = s.severity_id "
        "WHERE s.name = 'Critical' "
        "AND EXTRACT(YEAR FROM v.publish_date) = 2025;";

    const std::string COUNT_BY_TYPE =
        "SELECT vt.name, COUNT(v.vulnerability_id) AS total "
        "FROM vulnerability_types vt "
        "LEFT JOIN vulnerabilities v ON vt.type_id = v.type_id "
        "GROUP BY vt.name "
        "ORDER BY total DESC;";

    const std::string TOP5_PRODUCTS =
        "SELECT p.name, COUNT(*) AS total "
        "FROM vulnerabilities v "
        "JOIN products p ON v.product_id = p.product_id "
        "GROUP BY p.name "
        "ORDER BY total DESC "
        "LIMIT 5;";

    const std::string VULNS_WITHOUT_MITIGATION =
        "SELECT v.cve_id, v.description "
        "FROM vulnerabilities v "
        "LEFT JOIN mitigations m ON v.vulnerability_id = m.vulnerability_id "
        "WHERE m.mitigation_id IS NULL;";

    const std::string SQLI_PRODUCTS =
        "SELECT DISTINCT p.name, ven.name "
        "FROM vulnerabilities v "
        "JOIN vulnerability_types vt ON v.type_id = vt.type_id "
        "JOIN products p ON v.product_id = p.product_id "
        "JOIN vendors ven ON p.vendor_id = ven.vendor_id "
        "WHERE vt.name = 'SQL Injection';";

    const std::string AVG_CVSS =
        "SELECT name, (cvss_score_min + cvss_score_max)/2 AS avg_cvss "
        "FROM severity_levels;";

    const std::string COUNT_BY_YEAR_SEVERITY =
        "SELECT EXTRACT(YEAR FROM v.publish_date) AS year, "
        "s.name, COUNT(*) "
        "FROM vulnerabilities v "
        "JOIN severity_levels s ON v.severity_id = s.severity_id "
        "GROUP BY year, s.name "
        "ORDER BY year;";

    const std::string VENDORS_BY_VULNS =
        "SELECT ven.name, COUNT(*) AS total "
        "FROM vulnerabilities v "
        "JOIN products p ON v.product_id = p.product_id "
        "JOIN vendors ven ON p.vendor_id = ven.vendor_id "
        "GROUP BY ven.name "
        "ORDER BY total DESC;";

    const std::string VULNS_BY_PRODUCT =
        "SELECT v.cve_id, v.description, s.name "
        "FROM vulnerabilities v "
        "JOIN severity_levels s ON v.severity_id = s.severity_id "
        "WHERE v.product_id = $1;";


    // Добавление и удаление данных

    const std::string Q_INSERT_VENDOR =
        "INSERT INTO vendors (name, country) VALUES ($1, $2);";

    const std::string Q_INSERT_PRODUCT =
        "INSERT INTO products (vendor_id, name, version) "
        "SELECT vendor_id, $1, $2 FROM vendors WHERE name = $3;";

    const std::string Q_INSERT_VULNERABILITY =
        "INSERT INTO vulnerabilities "
        "(cve_id, product_id, type_id, severity_id, description, publish_date) "
        "VALUES ($1, $2, $3, $4, $5, $6);";

    const std::string Q_DELETE_VULNERABILITY =
        "DELETE FROM vulnerabilities WHERE cve_id = $1;";

    const std::string Q_INSERT_MITIGATION =
        "INSERT INTO mitigations "
        "(vulnerability_id, description, release_date) "
        "VALUES ($1, $2, $3);";

    const std::string Q_DELETE_PRODUCT =
        "DELETE FROM products WHERE name = $1;";
    

    // SQL-ИНЪЕКЦИИ (ДЕМОНСТРАЦИЯ)

    // 1. Обход фильтра
    // name = "' OR '1'='1"
    const std::string INJECTION_AUTH =
        "SELECT * FROM products WHERE name = '" ;

    // 2. Получение всех уязвимостей
    // input = "' UNION SELECT cve_id, description, publish_date FROM vulnerabilities --"
    const std::string INJECTION_UNION =
        "SELECT name FROM products WHERE name = '" ;

    // 3. Удаление таблицы (НЕ ВЫПОЛНЯТЬ!)
    // input = "'; DROP TABLE vulnerabilities; --"
}
