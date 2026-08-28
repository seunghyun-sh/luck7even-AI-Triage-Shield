"""Database helpers for SQLite tests and the Docker/RDS MySQL runtime."""

import sqlite3
import time
from pathlib import Path
from typing import Any

import click
from flask import current_app, g

try:
    import pymysql
    from pymysql.cursors import DictCursor
except ImportError:  # SQLite-only unit tests can still run before Docker setup.
    pymysql = None
    DictCursor = None


DATABASE_ERRORS: tuple[type[BaseException], ...] = (sqlite3.Error,)
INTEGRITY_ERRORS: tuple[type[BaseException], ...] = (sqlite3.IntegrityError,)
if pymysql is not None:
    DATABASE_ERRORS += (pymysql.MySQLError,)
    INTEGRITY_ERRORS += (pymysql.IntegrityError,)


class DatabaseConnection:
    """Expose one small query API across SQLite and PyMySQL."""

    def __init__(self, connection: Any, engine: str) -> None:
        self.connection = connection
        self.engine = engine

    def execute(self, query: str, params: tuple | list | None = None):
        if self.engine == "mysql":
            cursor = self.connection.cursor()
            if params is None:
                cursor.execute(query)
            else:
                cursor.execute(query.replace("?", "%s"), params)
            return cursor
        if params is None:
            return self.connection.execute(query)
        return self.connection.execute(query, params)

    def execute_script(self, script: str) -> None:
        if self.engine == "sqlite":
            self.connection.executescript(script)
            return
        for statement in script.split(";"):
            statement = statement.strip()
            if statement:
                self.execute(statement)

    def commit(self) -> None:
        self.connection.commit()

    def rollback(self) -> None:
        self.connection.rollback()

    def close(self) -> None:
        self.connection.close()


def _connect_sqlite() -> sqlite3.Connection:
    connection = sqlite3.connect(current_app.config["DATABASE"])
    connection.row_factory = sqlite3.Row

    def controlled_sleep(seconds: float) -> int:
        time.sleep(min(max(float(seconds), 0.0), 2.0))
        return 0

    connection.create_function("SLEEP", 1, controlled_sleep)
    return connection


def _connect_mysql():
    if pymysql is None:
        raise RuntimeError("PyMySQL is required when LAB_1_DB_ENGINE=mysql")
    return pymysql.connect(
        host=current_app.config["DB_HOST"],
        port=int(current_app.config["DB_PORT"]),
        user=current_app.config["DB_USER"],
        password=current_app.config["DB_PASSWORD"],
        database=current_app.config["DB_NAME"],
        charset="utf8mb4",
        cursorclass=DictCursor,
        autocommit=False,
        connect_timeout=int(current_app.config["DB_CONNECT_TIMEOUT"]),
    )


def get_db() -> DatabaseConnection:
    if "db" not in g:
        engine = current_app.config["DB_ENGINE"]
        if engine == "mysql":
            connection = _connect_mysql()
        elif engine == "sqlite":
            connection = _connect_sqlite()
        else:
            raise RuntimeError(f"Unsupported LAB_1_DB_ENGINE: {engine}")
        g.db = DatabaseConnection(connection, engine)
    return g.db


def close_db(_error=None) -> None:
    db = g.pop("db", None)
    if db is not None:
        db.close()


def _read_sql(filename: str) -> str:
    return Path(current_app.root_path, filename).read_text(encoding="utf-8")


def init_db() -> None:
    db = get_db()
    try:
        if current_app.config["DB_ENGINE"] == "mysql":
            db.execute_script(_read_sql("schema_mysql.sql"))
            db.execute_script(_read_sql("seed_mysql.sql"))
        else:
            db.execute_script(_read_sql("schema.sql"))
        db.commit()
    except Exception:
        db.rollback()
        raise
    click.echo("Lumi Market database initialized.")


def reset_db() -> None:
    db = get_db()
    try:
        if current_app.config["DB_ENGINE"] == "mysql":
            db.execute_script(_read_sql("seed_mysql.sql"))
        else:
            db.execute_script(_read_sql("schema.sql"))
        db.commit()
    except Exception:
        db.rollback()
        raise
    click.echo("Lumi Market database reset to seed data.")
