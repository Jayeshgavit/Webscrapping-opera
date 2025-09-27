#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import requests
from bs4 import BeautifulSoup
from datetime import datetime, timezone
import psycopg2
from psycopg2.extras import Json, RealDictCursor
from urllib.parse import urljoin
import os
from dotenv import load_dotenv

# =========================
# LOAD ENV
# =========================
load_dotenv()

DB_CONFIG = {
    "host": os.getenv("DB_HOST", "localhost"),
    "dbname": os.getenv("DB_NAME", "Opera"),
    "user": os.getenv("DB_USER", "postgres"),
    "password": os.getenv("DB_PASS", "623809"),
    "port": int(os.getenv("DB_PORT", 5432)),
}

BASE_URL = "https://security.opera.com/en/category/advisory/"
STAGING_TABLE = "staging_table"



BATCH_SIZE = 5

# Fields mapping
FIELD_MAP = {
    "cve id": "cve_id",
    "product": "product",
    "version": "version",
    "problem type": "problem_type",
    "problem description": "problem_type",
    "description": "description",
    "severity": "severity",
    "advisory": "advisory",
    "opera’s response": "opera_response",
    "opera's response": "opera_response",
    "affected versions": "affected_versions",
    "affected platforms": "affected_versions",
    "affected product": "product",
    "affected products": "product",
    "credits": "credits",
    "assigning cna": "assigning_cna",
}

# =========================
# DATABASE FUNCTIONS
# =========================
def init_db():
    conn = psycopg2.connect(**DB_CONFIG)
    cur = conn.cursor()
    # staging table
    cur.execute(f"""
        CREATE TABLE IF NOT EXISTS {STAGING_TABLE} (
            staging_id SERIAL PRIMARY KEY,
            vendor_name TEXT NOT NULL DEFAULT 'Opera',
            source_url TEXT UNIQUE,
            raw_data JSONB NOT NULL,
            processed BOOLEAN DEFAULT FALSE,
            processed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        );
    """)
    conn.commit()
    cur.close()
    return conn

def insert_batch(conn, advisories):
    cur = conn.cursor()
    for adv in advisories:
        cur.execute(
            f"""INSERT INTO {STAGING_TABLE} (vendor_name, source_url, raw_data, processed_at)
               VALUES (%s, %s, %s, %s)
               ON CONFLICT (source_url) DO NOTHING""",
            ("Opera", adv.get("url"), Json(adv), datetime.now(timezone.utc))
        )
    conn.commit()
    cur.close()

# =========================
# SCRAPER FUNCTIONS
# =========================
def parse_detail(url):
    res = requests.get(url, timeout=20, headers={"User-Agent": "Mozilla/5.0"})
    res.raise_for_status()
    soup = BeautifulSoup(res.text, "html.parser")
    content = soup.select_one("section.entry-content")
    details = {v: None for v in FIELD_MAP.values()}

    if content:
        # Headings + <p>
        for heading in content.find_all(re.compile("^h[1-6]$")):
            label = heading.get_text(strip=True).lower().rstrip(":：")
            if label in FIELD_MAP:
                field = FIELD_MAP[label]
                texts = []
                for sib in heading.find_next_siblings():
                    if sib.name and sib.name.startswith("h"):
                        break
                    if sib.name == "p":
                        texts.append(sib.get_text(" ", strip=True))
                if texts:
                    details[field] = " ".join(texts)

        # <p> + <strong> / <b>
        for p in content.find_all("p"):
            for strong in p.find_all(["strong","b"]):
                label = strong.get_text(strip=True).lower().rstrip(":：")
                if label in FIELD_MAP:
                    field = FIELD_MAP[label]
                    val_parts = []
                    for elem in strong.next_siblings:
                        if getattr(elem, "name", None) == "br":
                            break
                        if isinstance(elem, str):
                            val_parts.append(elem.strip())
                        elif hasattr(elem, "get_text"):
                            val_parts.append(elem.get_text(" ", strip=True))
                    val = " ".join(val_parts).strip(" :")
                    if val:
                        details[field] = val

        # Fallback regex
        text_all = content.get_text(" ", strip=True)
        if not details.get("cve_id"):
            m = re.search(r"(CVE-\d{4}-\d+)", text_all)
            if m: details["cve_id"] = m.group(1)
        if not details.get("product"):
            m = re.search(r"Affected\s+Product[s]?:\s*(.+?)(Version|Problem|Description|$)", text_all, re.IGNORECASE)
            if m: details["product"] = m.group(1).strip()
        if not details.get("version"):
            m = re.search(r"VERSION:\s*([^P]+)", text_all)
            if m: details["version"] = m.group(1).strip()
        if not details.get("problem_type"):
            m = re.search(r"PROBLEM TYPE:\s*([^D]+)", text_all)
            if m: details["problem_type"] = m.group(1).strip()
        if not details.get("description"):
            m = re.search(r"DESCRIPTION:\s*(.+?)(ASSIGNING CNA:|$)", text_all)
            if m: details["description"] = m.group(1).strip()
        if not details.get("assigning_cna"):
            m = re.search(r"ASSIGNING CNA:\s*(.+)", text_all)
            if m: details["assigning_cna"] = m.group(1).strip()

    return details

def fetch_advisories(conn):
    advisories = []
    next_url = BASE_URL
    advisory_counter = 1

    while next_url:
        print(f"[+] Scraping list page: {next_url}")
        res = requests.get(next_url, timeout=20, headers={"User-Agent": "Mozilla/5.0"})
        res.raise_for_status()
        soup = BeautifulSoup(res.text, "html.parser")
        posts = soup.select("article")
        for post in posts:
            title_tag = post.find("h2", class_="entry-title")
            link = title_tag.find("a")["href"] if title_tag else None
            title = title_tag.get_text(strip=True) if title_tag else None

            author_tag = post.find("span", class_="author")
            author = author_tag.get_text(strip=True) if author_tag else None

            date_tag = post.find("span", class_="entry-date")
            date = date_tag.get_text(strip=True) if date_tag else None

            summary_tag = post.find("section.entry-summary")
            summary = summary_tag.get_text(" ", strip=True) if summary_tag else None

            categories = [a.get_text(strip=True) for a in post.select("footer .cat-links a")]

            detail_data = parse_detail(link) if link else {v: None for v in FIELD_MAP.values()}
            cve_id = detail_data.get("cve_id")

            advisory_obj = {
                "url": link,
                "date": date,
                "title": title,
                "author": author,
                "cve_id": cve_id,
                "detail": detail_data,
                "summary": summary,
                "categories": categories
            }

            advisories.append(advisory_obj)
            advisory_counter += 1

            if len(advisories) >= BATCH_SIZE:
                insert_batch(conn, advisories)
                advisories.clear()

        # Pagination
        next_page = soup.select_one("div.nav-previous a")
        next_url = urljoin(BASE_URL, next_page["href"]) if next_page else None

    if advisories:
        insert_batch(conn, advisories)

# =========================
# MAIN
# =========================
if __name__ == "__main__":
    conn = init_db()
    try:
        fetch_advisories(conn)
        print("[+] Scraping complete and stored in staging table!")
    finally:
        conn.close()
