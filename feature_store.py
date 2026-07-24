#!/usr/bin/env python3
"""Feature Store: PostgreSQL-backed feature storage with SQLite fallback.

Stores behavioral feature vectors from the extraction pipeline,
supports querying by label/date/feature threshold, and exports
directly to pandas DataFrames for ML consumption.
"""

import json
import os
import sqlite3
import uuid
from datetime import datetime, timedelta
from typing import Optional

try:
    import psycopg2
    import psycopg2.extras
    HAS_PG = True
except ImportError:
    HAS_PG = False

try:
    import pandas as pd
    HAS_PANDAS = True
except ImportError:
    HAS_PANDAS = False


POSTGRES_SCHEMA = """
CREATE TABLE IF NOT EXISTS samples (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    apk_hash TEXT UNIQUE NOT NULL,
    label TEXT NOT NULL DEFAULT 'unknown',
    features JSONB NOT NULL,
    feature_count INTEGER DEFAULT 0,
    metadata JSONB DEFAULT '{}',
    timestamp TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_samples_label ON samples(label);
CREATE INDEX IF NOT EXISTS idx_samples_timestamp ON samples(timestamp);
CREATE INDEX IF NOT EXISTS idx_samples_hash ON samples(apk_hash);
CREATE INDEX IF NOT EXISTS idx_samples_feature_count ON samples(feature_count);
"""

SQLITE_SCHEMA = """
CREATE TABLE IF NOT EXISTS samples (
    id TEXT PRIMARY KEY,
    apk_hash TEXT UNIQUE NOT NULL,
    label TEXT NOT NULL DEFAULT 'unknown',
    features TEXT NOT NULL,
    feature_count INTEGER DEFAULT 0,
    metadata TEXT DEFAULT '{}',
    timestamp TEXT DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_samples_label ON samples(label);
CREATE INDEX IF NOT EXISTS idx_samples_timestamp ON samples(timestamp);
"""


class FeatureStore:
    def __init__(self, postgres_url: Optional[str] = None,
                 sqlite_path: Optional[str] = "./feature_store.db"):
        self.postgres_url = postgres_url
        self.sqlite_path = sqlite_path
        self.use_postgres = False
        self.pg_conn = None
        self.sqlite_conn = None

        if postgres_url and HAS_PG:
            try:
                self.pg_conn = psycopg2.connect(postgres_url)
                self.pg_conn.autocommit = True
                with self.pg_conn.cursor() as cur:
                    cur.execute(POSTGRES_SCHEMA)
                self.use_postgres = True
                print(f"[+] Connected to PostgreSQL: {postgres_url}")
            except Exception as e:
                print(f"[!] PostgreSQL connection failed: {e}")
                print("[*] Falling back to SQLite")

        if not self.use_postgres:
            os.makedirs(os.path.dirname(sqlite_path) or ".", exist_ok=True)
            self.sqlite_conn = sqlite3.connect(sqlite_path)
            self.sqlite_conn.row_factory = sqlite3.Row
            self.sqlite_conn.executescript(SQLITE_SCHEMA)
            print(f"[+] Using SQLite: {sqlite_path}")

    def insert(self, apk_hash: str, label: str, features: dict,
               metadata: dict = None) -> str:
        sample_id = str(uuid.uuid4())
        feature_count = len(features)
        meta = metadata or {}
        now = datetime.utcnow().isoformat()

        if self.use_postgres:
            with self.pg_conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO samples (id, apk_hash, label, features, feature_count, metadata, timestamp)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (apk_hash) DO UPDATE SET
                        label = EXCLUDED.label,
                        features = EXCLUDED.features,
                        feature_count = EXCLUDED.feature_count,
                        metadata = EXCLUDED.metadata,
                        timestamp = EXCLUDED.timestamp
                """, (sample_id, apk_hash, label, json.dumps(features),
                      feature_count, json.dumps(meta), now))
        else:
            self.sqlite_conn.execute(
                "INSERT OR REPLACE INTO samples (id, apk_hash, label, features, feature_count, metadata, timestamp) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (sample_id, apk_hash, label, json.dumps(features),
                 feature_count, json.dumps(meta), now)
            )
            self.sqlite_conn.commit()

        return sample_id

    def bulk_insert(self, records: list[dict]) -> int:
        count = 0
        if self.use_postgres:
            with self.pg_conn.cursor() as cur:
                for rec in records:
                    sample_id = str(uuid.uuid4())
                    features = rec.get("features", {})
                    cur.execute("""
                        INSERT INTO samples (id, apk_hash, label, features, feature_count, metadata, timestamp)
                        VALUES (%s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (apk_hash) DO UPDATE SET
                            label = EXCLUDED.label,
                            features = EXCLUDED.features,
                            feature_count = EXCLUDED.feature_count,
                            timestamp = EXCLUDED.timestamp
                    """, (
                        sample_id,
                        rec["apk_hash"],
                        rec.get("label", "unknown"),
                        json.dumps(features),
                        len(features),
                        json.dumps(rec.get("metadata", {})),
                        datetime.utcnow().isoformat(),
                    ))
                    count += 1
        else:
            for rec in records:
                sample_id = str(uuid.uuid4())
                features = rec.get("features", {})
                self.sqlite_conn.execute(
                    "INSERT OR REPLACE INTO samples (id, apk_hash, label, features, feature_count, metadata, timestamp) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (sample_id, rec["apk_hash"], rec.get("label", "unknown"),
                     json.dumps(features), len(features),
                     json.dumps(rec.get("metadata", {})),
                     datetime.utcnow().isoformat())
                )
                count += 1
            self.sqlite_conn.commit()

        print(f"[+] Inserted {count} records")
        return count

    def query_by_label(self, label: str) -> list[dict]:
        if self.use_postgres:
            with self.pg_conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("SELECT * FROM samples WHERE label = %s", (label,))
                return [dict(row) for row in cur.fetchall()]
        else:
            rows = self.sqlite_conn.execute(
                "SELECT * FROM samples WHERE label = ?", (label,)
            ).fetchall()
            return [dict(row) for row in rows]

    def query_by_date_range(self, start: str, end: str) -> list[dict]:
        if self.use_postgres:
            with self.pg_conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    "SELECT * FROM samples WHERE timestamp BETWEEN %s AND %s",
                    (start, end)
                )
                return [dict(row) for row in cur.fetchall()]
        else:
            rows = self.sqlite_conn.execute(
                "SELECT * FROM samples WHERE timestamp BETWEEN ? AND ?",
                (start, end)
            ).fetchall()
            return [dict(row) for row in rows]

    def query_by_feature_threshold(self, feature_name: str,
                                    min_value: float) -> list[dict]:
        if self.use_postgres:
            query = """
                SELECT * FROM samples
                WHERE (features->>%s)::float >= %s
            """
            with self.pg_conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(query, (feature_name, min_value))
                return [dict(row) for row in cur.fetchall()]
        else:
            rows = self.sqlite_conn.execute("SELECT * FROM samples").fetchall()
            results = []
            for row in rows:
                features = json.loads(row["features"])
                if features.get(feature_name, 0) >= min_value:
                    results.append(dict(row))
            return results

    def query_all(self) -> list[dict]:
        if self.use_postgres:
            with self.pg_conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("SELECT * FROM samples ORDER BY timestamp")
                return [dict(row) for row in cur.fetchall()]
        else:
            rows = self.sqlite_conn.execute(
                "SELECT * FROM samples ORDER BY timestamp"
            ).fetchall()
            return [dict(row) for row in rows]

    def count(self, label: Optional[str] = None) -> int:
        if self.use_postgres:
            with self.pg_conn.cursor() as cur:
                if label:
                    cur.execute("SELECT COUNT(*) FROM samples WHERE label = %s", (label,))
                else:
                    cur.execute("SELECT COUNT(*) FROM samples")
                return cur.fetchone()[0]
        else:
            if label:
                return self.sqlite_conn.execute(
                    "SELECT COUNT(*) FROM samples WHERE label = ?", (label,)
                ).fetchone()[0]
            return self.sqlite_conn.execute("SELECT COUNT(*) FROM samples").fetchone()[0]

    def to_dataframe(self, label: Optional[str] = None) -> "pd.DataFrame":
        if not HAS_PANDAS:
            raise ImportError("pandas not installed: pip install pandas")

        records = self.query_by_label(label) if label else self.query_all()
        if not records:
            return pd.DataFrame()

        rows = []
        for rec in records:
            features = json.loads(rec["features"]) if isinstance(rec["features"], str) else rec["features"]
            row = {
                "id": rec["id"],
                "apk_hash": rec["apk_hash"],
                "label": rec["label"],
                "timestamp": rec["timestamp"],
            }
            row.update(features)
            rows.append(row)

        return pd.DataFrame(rows)

    def export_to_csv(self, path: str, label: Optional[str] = None):
        df = self.to_dataframe(label)
        if hasattr(df, "to_csv"):
            df.to_csv(path, index=False)
            return path
        raise ImportError("pandas not installed")

    def export_to_parquet(self, path: str, label: Optional[str] = None):
        df = self.to_dataframe(label)
        if hasattr(df, "to_parquet"):
            df.to_parquet(path, index=False)
            return path
        raise ImportError("pandas not installed")

    def to_feature_matrix(self, feature_names: Optional[list[str]] = None,
                          label_filter: Optional[str] = None) -> tuple:
        df = self.to_dataframe(label_filter)

        if df.empty:
            return [], pd.DataFrame(), []

        if feature_names is None:
            exclude = {"id", "apk_hash", "label", "timestamp", "metadata"}
            feature_names = [c for c in df.columns if c not in exclude]

        X = df[feature_names].fillna(0)
        y = df["label"].tolist()

        return feature_names, X, y

    def get_label_distribution(self) -> dict:
        if self.use_postgres:
            with self.pg_conn.cursor() as cur:
                cur.execute("SELECT label, COUNT(*) FROM samples GROUP BY label")
                return {row[0]: row[1] for row in cur.fetchall()}
        else:
            rows = self.sqlite_conn.execute(
                "SELECT label, COUNT(*) FROM samples GROUP BY label"
            ).fetchall()
            return {row[0]: row[1] for row in rows}

    def export_features_json(self, output_path: str):
        records = self.query_all()
        feature_set = set()
        samples = []

        for rec in records:
            features = json.loads(rec["features"]) if isinstance(rec["features"], str) else rec["features"]
            feature_set.update(features.keys())
            samples.append({
                "sample_id": rec["apk_hash"],
                "label": rec["label"],
                "features": features,
            })

        data = {
            "feature_names": sorted(feature_set),
            "samples": samples,
        }

        with open(output_path, "w") as f:
            json.dump(data, f, indent=2)
        print(f"[+] Exported {len(samples)} samples to {output_path}")

    def close(self):
        if self.pg_conn:
            self.pg_conn.close()
        if self.sqlite_conn:
            self.sqlite_conn.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Feature Store Management")
    sub = parser.add_subparsers(dest="command")

    insert_p = sub.add_parser("insert", help="Insert from features.json")
    insert_p.add_argument("features_json", help="Path to features.json")
    insert_p.add_argument("--pg", help="PostgreSQL URL")
    insert_p.add_argument("--db", default="./feature_store.db", help="SQLite path")

    query_p = sub.add_parser("query", help="Query stored features")
    query_p.add_argument("--label", help="Filter by label")
    query_p.add_argument("--pg", help="PostgreSQL URL")
    query_p.add_argument("--db", default="./feature_store.db")
    query_p.add_argument("--export", help="Export to features.json")

    stats_p = sub.add_parser("stats", help="Show statistics")
    stats_p.add_argument("--pg", help="PostgreSQL URL")
    stats_p.add_argument("--db", default="./feature_store.db")

    args = parser.parse_args()

    if args.command == "insert":
        with FeatureStore(postgres_url=getattr(args, "pg", None),
                         sqlite_path=args.db) as store:
            with open(args.features_json) as f:
                data = json.load(f)

            records = []
            for sample in data.get("samples", []):
                records.append({
                    "apk_hash": sample.get("sample_id", str(uuid.uuid4())),
                    "label": sample.get("label", "unknown"),
                    "features": sample.get("features", {}),
                })
            store.bulk_insert(records)

    elif args.command == "query":
        with FeatureStore(postgres_url=getattr(args, "pg", None),
                         sqlite_path=args.db) as store:
            if args.label:
                results = store.query_by_label(args.label)
            else:
                results = store.query_all()

            print(f"Found {len(results)} samples")
            for r in results[:5]:
                features = json.loads(r["features"]) if isinstance(r["features"], str) else r["features"]
                print(f"  {r['apk_hash'][:16]}... label={r['label']} features={len(features)}")

            if args.export:
                store.export_features_json(args.export)

    elif args.command == "stats":
        with FeatureStore(postgres_url=getattr(args, "pg", None),
                         sqlite_path=args.db) as store:
            print(f"Total samples: {store.count()}")
            dist = store.get_label_distribution()
            for label, count in dist.items():
                print(f"  {label}: {count}")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
