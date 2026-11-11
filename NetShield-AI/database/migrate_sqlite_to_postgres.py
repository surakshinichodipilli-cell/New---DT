import os
import sqlite3
from pathlib import Path

import psycopg
from psycopg import sql
from psycopg.rows import dict_row
from dotenv import load_dotenv

load_dotenv()

from database import db_helper


TABLES = (
    "users",
    "url_scans",
    "devices",
    "network_scans",
    "alerts",
    "device_inventory",
    "trusted_devices",
)
BATCH_SIZE = 500


def migrate_sqlite_to_postgres(source_path, database_url):
    source_path = Path(source_path)
    if not source_path.is_file():
        raise FileNotFoundError(f"SQLite database not found: {source_path}")
    if not db_helper.DATABASE_URL:
        raise ValueError("Set DATABASE_URL to the destination PostgreSQL connection string.")
    if database_url and database_url != db_helper.DATABASE_URL:
        raise ValueError("The destination URL must match the DATABASE_URL environment setting.")
    database_url = db_helper.DATABASE_URL

    db_helper.init_db()
    copied_counts = {}
    with sqlite3.connect(source_path) as source, psycopg.connect(
        database_url,
        row_factory=dict_row,
    ) as destination:
        source.row_factory = sqlite3.Row
        for table in TABLES:
            row = destination.execute(
                sql.SQL("SELECT COUNT(*) AS count FROM {}").format(sql.Identifier(table))
            ).fetchone()
            if row["count"]:
                raise RuntimeError(
                    f"PostgreSQL table '{table}' is not empty. Migration stopped without "
                    "overwriting existing destination data."
                )

        for table in TABLES:
            columns = [
                row["name"]
                for row in source.execute(
                    f"PRAGMA table_info({table})"
                ).fetchall()
            ]
            if not columns:
                continue

            statement = sql.SQL("INSERT INTO {} ({}) VALUES ({})").format(
                sql.Identifier(table),
                sql.SQL(", ").join(map(sql.Identifier, columns)),
                sql.SQL(", ").join(sql.Placeholder() for _ in columns),
            )
            source_cursor = source.execute(f"SELECT * FROM {table}")
            destination_cursor = destination.cursor()
            copied = 0
            while rows := source_cursor.fetchmany(BATCH_SIZE):
                destination_cursor.executemany(
                    statement,
                    [tuple(row[column] for column in columns) for row in rows],
                )
                copied += len(rows)
            copied_counts[table] = copied

        for table in TABLES:
            destination.execute(
                sql.SQL(
                    """
                    SELECT setval(
                        pg_get_serial_sequence(%s, 'id'),
                        COALESCE(MAX(id), 1),
                        COUNT(*) > 0
                    )
                    FROM {}
                    """
                ).format(sql.Identifier(table)),
                (table,),
            )

    return copied_counts


def main():
    load_dotenv()
    source_path = os.getenv(
        "SQLITE_DATABASE_PATH",
        str(Path(__file__).resolve().parent / "netshield.db"),
    )
    database_url = db_helper.DATABASE_URL
    copied_counts = migrate_sqlite_to_postgres(source_path, database_url)
    print("SQLite data migration completed. Rows copied:")
    for table, count in copied_counts.items():
        print(f"  {table}: {count}")
    print("The SQLite source database was not changed.")


if __name__ == "__main__":
    main()
