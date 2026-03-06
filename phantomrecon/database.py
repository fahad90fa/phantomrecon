from __future__ import annotations

import json
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Generator, Optional

DB_PATH = Path.home() / ".phantomrecon" / "history.db"


def _ensure_dir() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)


def get_connection() -> sqlite3.Connection:
    _ensure_dir()
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


@contextmanager
def db_conn() -> Generator[sqlite3.Connection, None, None]:
    conn = get_connection()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db() -> None:
    with db_conn() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS scans (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                target      TEXT NOT NULL,
                start_time  REAL NOT NULL,
                end_time    REAL,
                duration    REAL,
                total_requests INTEGER DEFAULT 0,
                profile     TEXT,
                notes       TEXT,
                raw_json    TEXT,
                created_at  REAL DEFAULT (strftime('%s','now'))
            );

            CREATE TABLE IF NOT EXISTS findings (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id     INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                title       TEXT NOT NULL,
                severity    TEXT NOT NULL,
                module      TEXT NOT NULL,
                url         TEXT NOT NULL,
                description TEXT,
                evidence    TEXT,
                recommendation TEXT,
                cve         TEXT,
                cvss        REAL,
                timestamp   REAL
            );

            CREATE TABLE IF NOT EXISTS paths (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id         INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                url             TEXT NOT NULL,
                status_code     INTEGER,
                content_length  INTEGER,
                content_type    TEXT,
                response_time   REAL,
                is_directory    INTEGER DEFAULT 0,
                redirect_to     TEXT,
                title           TEXT
            );

            CREATE TABLE IF NOT EXISTS technologies (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id     INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                name        TEXT NOT NULL,
                version     TEXT,
                evidence    TEXT
            );

            CREATE TABLE IF NOT EXISTS screenshots (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id     INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                url         TEXT NOT NULL,
                file_path   TEXT NOT NULL,
                taken_at    REAL DEFAULT (strftime('%s','now'))
            );

            CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target);
            CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
            CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
            CREATE INDEX IF NOT EXISTS idx_paths_scan ON paths(scan_id);

            CREATE VIRTUAL TABLE IF NOT EXISTS findings_fts USING fts5(
                title, description, evidence, url,
                content='findings', content_rowid='id'
            );

            CREATE TRIGGER IF NOT EXISTS findings_ai AFTER INSERT ON findings BEGIN
                INSERT INTO findings_fts(rowid, title, description, evidence, url)
                VALUES (new.id, new.title, new.description, new.evidence, new.url);
            END;
        """)


class ScanDatabase:
    def __init__(self) -> None:
        init_db()

    def save_scan(self, result: Any, profile: str = "", notes: str = "") -> int:
        from .models import ScanResult
        raw = self._result_to_dict(result)
        with db_conn() as conn:
            cur = conn.execute(
                """INSERT INTO scans (target, start_time, end_time, duration, total_requests, profile, notes, raw_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    result.target,
                    result.start_time,
                    result.end_time,
                    result.duration,
                    result.total_requests,
                    profile,
                    notes,
                    json.dumps(raw),
                ),
            )
            scan_id = cur.lastrowid

            for f in result.findings:
                conn.execute(
                    """INSERT INTO findings (scan_id, title, severity, module, url, description,
                       evidence, recommendation, cve, cvss, timestamp)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        scan_id, f.title, f.severity.value, f.module.value,
                        f.url, f.description, f.evidence, f.recommendation,
                        f.cve, f.cvss, f.timestamp,
                    ),
                )

            for p in result.discovered_paths:
                conn.execute(
                    """INSERT INTO paths (scan_id, url, status_code, content_length, content_type,
                       response_time, is_directory, redirect_to, title)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        scan_id, p.url, p.status_code, p.content_length,
                        p.content_type, p.response_time, int(p.is_directory),
                        p.redirect_to, p.title,
                    ),
                )

            for tech, info in result.technologies.items():
                version = info.get("version") if isinstance(info, dict) else None
                evidence = info.get("evidence", "") if isinstance(info, dict) else str(info)
                conn.execute(
                    "INSERT INTO technologies (scan_id, name, version, evidence) VALUES (?, ?, ?, ?)",
                    (scan_id, tech, version, evidence),
                )

        return scan_id

    def list_scans(self, limit: int = 100, target_filter: str = "") -> list[dict]:
        with db_conn() as conn:
            if target_filter:
                rows = conn.execute(
                    """SELECT id, target, start_time, end_time, duration, total_requests, profile,
                              (SELECT COUNT(*) FROM findings WHERE scan_id=s.id) as finding_count,
                              (SELECT COUNT(*) FROM paths WHERE scan_id=s.id) as path_count
                       FROM scans s WHERE target LIKE ? ORDER BY start_time DESC LIMIT ?""",
                    (f"%{target_filter}%", limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    """SELECT id, target, start_time, end_time, duration, total_requests, profile,
                              (SELECT COUNT(*) FROM findings WHERE scan_id=s.id) as finding_count,
                              (SELECT COUNT(*) FROM paths WHERE scan_id=s.id) as path_count
                       FROM scans s ORDER BY start_time DESC LIMIT ?""",
                    (limit,),
                ).fetchall()
            return [dict(r) for r in rows]

    def get_scan(self, scan_id: int) -> Optional[dict]:
        with db_conn() as conn:
            row = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
            if not row:
                return None
            d = dict(row)
            d["findings"] = [dict(r) for r in conn.execute(
                "SELECT * FROM findings WHERE scan_id=?", (scan_id,)
            ).fetchall()]
            d["paths"] = [dict(r) for r in conn.execute(
                "SELECT * FROM paths WHERE scan_id=?", (scan_id,)
            ).fetchall()]
            d["technologies"] = [dict(r) for r in conn.execute(
                "SELECT * FROM technologies WHERE scan_id=?", (scan_id,)
            ).fetchall()]
            return d

    def delete_scan(self, scan_id: int) -> None:
        with db_conn() as conn:
            conn.execute("DELETE FROM scans WHERE id=?", (scan_id,))

    def search_findings(self, query: str, limit: int = 50) -> list[dict]:
        with db_conn() as conn:
            rows = conn.execute(
                """SELECT f.*, s.target FROM findings f
                   JOIN scans s ON s.id=f.scan_id
                   WHERE f.id IN (
                       SELECT rowid FROM findings_fts WHERE findings_fts MATCH ?
                   ) LIMIT ?""",
                (query, limit),
            ).fetchall()
            return [dict(r) for r in rows]

    def get_findings_timeline(self, target: str = "") -> list[dict]:
        with db_conn() as conn:
            if target:
                rows = conn.execute(
                    """SELECT s.start_time, f.severity, COUNT(*) as count
                       FROM findings f JOIN scans s ON s.id=f.scan_id
                       WHERE s.target LIKE ?
                       GROUP BY s.id, f.severity ORDER BY s.start_time""",
                    (f"%{target}%",),
                ).fetchall()
            else:
                rows = conn.execute(
                    """SELECT s.start_time, f.severity, COUNT(*) as count
                       FROM findings f JOIN scans s ON s.id=f.scan_id
                       GROUP BY s.id, f.severity ORDER BY s.start_time""",
                ).fetchall()
            return [dict(r) for r in rows]

    def diff_scans(self, scan_id_a: int, scan_id_b: int) -> dict:
        a = self.get_scan(scan_id_a)
        b = self.get_scan(scan_id_b)
        if not a or not b:
            return {}

        def finding_key(f: dict) -> str:
            return f"{f['title']}|{f['url']}|{f['severity']}"

        a_keys = {finding_key(f): f for f in a["findings"]}
        b_keys = {finding_key(f): f for f in b["findings"]}

        new_findings = [b_keys[k] for k in b_keys if k not in a_keys]
        fixed_findings = [a_keys[k] for k in a_keys if k not in b_keys]
        common = [b_keys[k] for k in b_keys if k in a_keys]

        a_paths = {p["url"] for p in a["paths"]}
        b_paths = {p["url"] for p in b["paths"]}
        new_paths = [p for p in b["paths"] if p["url"] not in a_paths]
        removed_paths = [{"url": u} for u in (a_paths - b_paths)]

        return {
            "scan_a": {"id": scan_id_a, "target": a["target"], "start_time": a["start_time"]},
            "scan_b": {"id": scan_id_b, "target": b["target"], "start_time": b["start_time"]},
            "new_findings": new_findings,
            "fixed_findings": fixed_findings,
            "common_findings": common,
            "new_paths": new_paths,
            "removed_paths": removed_paths,
        }

    def save_screenshot(self, scan_id: int, url: str, file_path: str) -> None:
        with db_conn() as conn:
            conn.execute(
                "INSERT INTO screenshots (scan_id, url, file_path) VALUES (?, ?, ?)",
                (scan_id, url, file_path),
            )

    def get_screenshots(self, scan_id: int) -> list[dict]:
        with db_conn() as conn:
            return [dict(r) for r in conn.execute(
                "SELECT * FROM screenshots WHERE scan_id=?", (scan_id,)
            ).fetchall()]

    def get_stats(self) -> dict:
        with db_conn() as conn:
            total_scans = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
            total_findings = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
            total_paths = conn.execute("SELECT COUNT(*) FROM paths").fetchone()[0]
            sev_counts = {
                row[0]: row[1]
                for row in conn.execute(
                    "SELECT severity, COUNT(*) FROM findings GROUP BY severity"
                ).fetchall()
            }
            top_targets = [
                dict(r) for r in conn.execute(
                    """SELECT target, COUNT(*) as scans FROM scans
                       GROUP BY target ORDER BY scans DESC LIMIT 10"""
                ).fetchall()
            ]
        return {
            "total_scans": total_scans,
            "total_findings": total_findings,
            "total_paths": total_paths,
            "severity_counts": sev_counts,
            "top_targets": top_targets,
        }

    def _result_to_dict(self, result: Any) -> dict:
        return {
            "target": result.target,
            "start_time": result.start_time,
            "end_time": result.end_time,
            "duration": result.duration,
            "total_requests": result.total_requests,
            "technologies": result.technologies,
            "ssl_info": result.ssl_info,
            "headers_analysis": result.headers_analysis,
            "errors": result.errors,
            "findings": [
                {
                    "title": f.title, "severity": f.severity.value,
                    "module": f.module.value, "url": f.url,
                    "description": f.description, "evidence": f.evidence,
                    "recommendation": f.recommendation, "cve": f.cve,
                }
                for f in result.findings
            ],
            "discovered_paths": [
                {
                    "url": p.url, "status_code": p.status_code,
                    "content_length": p.content_length,
                    "content_type": p.content_type,
                }
                for p in result.discovered_paths
            ],
        }
