CREATE TABLE vendors (
    vendor_id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL UNIQUE,
    country VARCHAR(50)
);

CREATE TABLE products (
    product_id SERIAL PRIMARY KEY,
    vendor_id INTEGER NOT NULL,
    name VARCHAR(100) NOT NULL,
    version VARCHAR(50),

    CONSTRAINT fk_products_vendor
        FOREIGN KEY (vendor_id)
        REFERENCES vendors(vendor_id)
        ON DELETE CASCADE
);

CREATE TABLE vulnerability_types (
    type_id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL UNIQUE,
    description TEXT
);

CREATE TABLE severity_levels (
    severity_id SERIAL PRIMARY KEY,
    name VARCHAR(50) NOT NULL UNIQUE,
    cvss_score_min NUMERIC(3,1),
    cvss_score_max NUMERIC(3,1)
);

CREATE TABLE vulnerabilities (
    vulnerability_id SERIAL PRIMARY KEY,
    cve_id VARCHAR(20) NOT NULL UNIQUE,
    product_id INTEGER NOT NULL,
    type_id INTEGER NOT NULL,
    severity_id INTEGER NOT NULL,
    description TEXT,
    publish_date DATE NOT NULL,

    CONSTRAINT fk_vulnerabilities_product
        FOREIGN KEY (product_id)
        REFERENCES products(product_id)
        ON DELETE CASCADE,

    CONSTRAINT fk_vulnerabilities_type
        FOREIGN KEY (type_id)
        REFERENCES vulnerability_types(type_id),

    CONSTRAINT fk_vulnerabilities_severity
        FOREIGN KEY (severity_id)
        REFERENCES severity_levels(severity_id)
);

CREATE TABLE mitigations (
    mitigation_id SERIAL PRIMARY KEY,
    vulnerability_id INTEGER NOT NULL,
    description TEXT NOT NULL,
    release_date DATE,

    CONSTRAINT fk_mitigations_vulnerability
        FOREIGN KEY (vulnerability_id)
        REFERENCES vulnerabilities(vulnerability_id)
        ON DELETE CASCADE
);
