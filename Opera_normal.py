
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import json
import re
from datetime import datetime
import psycopg2
import logging
from dotenv import load_dotenv

# ------------------------- SETUP -------------------------
logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)-8s | %(message)s")
logger = logging.getLogger("normalize_opera")

load_dotenv()

DB_CONFIG = {
    "host": os.getenv("DB_HOST", "localhost"),
    "dbname": os.getenv("DB_NAME", "Opera"),
    "user": os.getenv("DB_USER", "postgres"),
    "password": os.getenv("DB_PASS", "623809"),
    "port": int(os.getenv("DB_PORT", 5432)),
}

# ------------------------- TABLE NAMES -------------------------
STAGING_TABLE = "staging_table"
TABLE_VENDORS = "vendors"
TABLE_ADVISORIES = "advisories"
TABLE_CVES = "cves"
TABLE_ADV_CVE_MAP = "advisory_cve_map"
TABLE_CVE_PRODUCT_MAP = "cve_product_map"

# ------------------------- DB HELPERS -------------------------
def get_connection():
    return psycopg2.connect(**DB_CONFIG)

# ------------------------- UTILITIES -------------------------
def parse_date(d):
    """Parse date from multiple formats, no slicing"""
    if not d:
        return None
    formats = ("%Y-%m-%d", "%B %d, %Y", "%b %d, %Y")
    for fmt in formats:
        try:
            return datetime.strptime(d.strip(), fmt).date()
        except Exception:
            continue
    return None

def join_cwe(problem_type_list):
    """Extract CWEs from problem_type strings"""
    if not problem_type_list:
        return None
    cwe_set = set()
    for pt in problem_type_list:
        if not pt:
            continue
        matches = re.findall(r"CWE-\d+", pt, re.IGNORECASE)
        for m in matches:
            cwe_set.add(m.upper())
    return ",".join(sorted(cwe_set)) if cwe_set else None

def get_or_create_vendor_id(cur, vendor_name="Opera"):
    cur.execute(f"SELECT vendor_id FROM {TABLE_VENDORS} WHERE vendor_name=%s", (vendor_name,))
    row = cur.fetchone()
    if row:
        return row[0]
    cur.execute(f"INSERT INTO {TABLE_VENDORS} (vendor_name) VALUES (%s) RETURNING vendor_id", (vendor_name,))
    return cur.fetchone()[0]

def get_next_advisory_id(cur):
    """Generate incrementing advisory ID like Opera-2025-001"""
    year = datetime.utcnow().year
    cur.execute(f"SELECT advisory_id FROM {TABLE_ADVISORIES} WHERE advisory_id LIKE %s ORDER BY advisory_id DESC LIMIT 1", (f"Opera-{year}-%",))
    row = cur.fetchone()
    last_num = 0
    if row:
        try:
            last_num = int(row[0].split("-")[-1])
        except:
            last_num = 0
    return f"Opera-{year}-{last_num+1:03d}"

# ------------------------- ENSURE TABLES -------------------------
def ensure_tables():
    with get_connection() as conn, conn.cursor() as cur:
        cur.execute(f"""
            CREATE TABLE IF NOT EXISTS {TABLE_VENDORS} (
                vendor_id SERIAL PRIMARY KEY,
                vendor_name TEXT NOT NULL UNIQUE
            );
        """)
        cur.execute(f"""
            CREATE TABLE IF NOT EXISTS {TABLE_ADVISORIES} (
                advisory_id TEXT PRIMARY KEY,
                vendor_id INTEGER REFERENCES {TABLE_VENDORS}(vendor_id),
                title TEXT,
                severity TEXT,
                initial_release_date DATE,
                latest_update_date DATE,
                advisory_url TEXT
            );
        """)
        cur.execute(f"""
            CREATE TABLE IF NOT EXISTS {TABLE_CVES} (
                cve_id TEXT PRIMARY KEY,
                cwe_id TEXT,
                description TEXT,
                severity TEXT,
                cvss_score NUMERIC(3,1),
                cvss_vector TEXT,
                initial_release_date DATE,
                latest_update_date DATE,
                reference_url TEXT
            );
        """)
        cur.execute(f"""
            CREATE TABLE IF NOT EXISTS {TABLE_ADV_CVE_MAP} (
                advisory_id TEXT REFERENCES {TABLE_ADVISORIES}(advisory_id) ON DELETE CASCADE,
                cve_id TEXT REFERENCES {TABLE_CVES}(cve_id) ON DELETE CASCADE,
                PRIMARY KEY (advisory_id, cve_id)
            );
        """)
        cur.execute(f"""
            CREATE TABLE IF NOT EXISTS {TABLE_CVE_PRODUCT_MAP} (
                qs_id SERIAL NOT NULL UNIQUE,
                cve_id TEXT PRIMARY KEY REFERENCES {TABLE_CVES}(cve_id) ON DELETE CASCADE,
                affected_products_cpe JSONB,
                recommendations TEXT
            );
        """)
        cur.execute(f"CREATE INDEX IF NOT EXISTS idx_cpe_gin ON {TABLE_CVE_PRODUCT_MAP} USING GIN (affected_products_cpe);")
        conn.commit()
        logger.info("Normalized tables created/checked.")

# ------------------------- NORMALIZATION -------------------------
def normalize_staging():
    with get_connection() as conn, conn.cursor() as cur:
        cur.execute(f"""
            SELECT staging_id, raw_data, source_url
            FROM {STAGING_TABLE}
            WHERE vendor_name='Opera' AND processed=FALSE
            ORDER BY staging_id
        """)
        rows = cur.fetchall()
        logger.info("[+] Found %d rows to normalize", len(rows))

        for staging_id, raw_json, source_url in rows:
            try:
                data = {}
                if raw_json:
                    try:
                        data = json.loads(raw_json) if isinstance(raw_json, str) else raw_json
                    except Exception:
                        data = {}

                detail = data.get("detail") or {}

                # Vendor
                vendor_id = get_or_create_vendor_id(cur)

                # Advisory
                advisory_title = data.get("title")
                advisory_url = data.get("url") or source_url
                severity = data.get("severity") or detail.get("severity")
                initial_date = parse_date(data.get("date"))
                advisory_id = get_next_advisory_id(cur)

                # Insert advisory
                cur.execute(f"""
                    INSERT INTO {TABLE_ADVISORIES} 
                    (advisory_id, vendor_id, title, severity, initial_release_date, latest_update_date, advisory_url)
                    VALUES (%s,%s,%s,%s,%s,%s,%s)
                    ON CONFLICT (advisory_id) DO NOTHING
                """, (advisory_id, vendor_id, advisory_title, severity, initial_date, None, advisory_url))

                # CVE (from outer JSON)
                cve_id = data.get("cve_id")
                description = detail.get("description") or None
                problem_type = detail.get("problem_type") or None
                cwe_id = join_cwe([problem_type]) if problem_type else None

                if cve_id:
                    # Insert CVE with severity NULL and reference_url NULL
                    cur.execute(f"""
                        INSERT INTO {TABLE_CVES} 
                        (cve_id, description, cwe_id, severity, cvss_score, cvss_vector, initial_release_date, latest_update_date, reference_url)
                        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
                        ON CONFLICT (cve_id) DO NOTHING
                    """, (cve_id, description, cwe_id, None, None, None, None, None, None))

                    # Mapping advisory <-> CVE
                    cur.execute(f"""
                        INSERT INTO {TABLE_ADV_CVE_MAP} (advisory_id, cve_id)
                        VALUES (%s,%s)
                        ON CONFLICT (advisory_id, cve_id) DO NOTHING
                    """, (advisory_id, cve_id))

                    # Product mapping
                    cur.execute(f"""
                        INSERT INTO {TABLE_CVE_PRODUCT_MAP} (cve_id, affected_products_cpe, recommendations)
                        VALUES (%s,%s,%s)
                        ON CONFLICT (cve_id) DO NOTHING
                    """, (cve_id, None, detail.get("opera_response")))

                # Mark staging processed
                cur.execute(f"""
                    UPDATE {STAGING_TABLE} SET processed=TRUE, processed_at=NOW()
                    WHERE staging_id=%s
                """, (staging_id,))

                conn.commit()
                logger.info("[+] Normalized staging_id %s -> advisory %s, CVE %s", staging_id, advisory_id, cve_id)

            except Exception as e:
                conn.rollback()
                logger.error("[!] Error processing staging_id %s: %s", staging_id, e)

# ------------------------- MAIN -------------------------
if __name__ == "__main__":
    ensure_tables()
    normalize_staging()
    logger.info("[+] Opera normalization complete!")
