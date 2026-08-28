"""Database setup shared by NovaStream routes."""

from __future__ import annotations

from sqlalchemy import Column, Integer, MetaData, String, Table, Text, create_engine, func, select, text


class Database:
    def __init__(self, database_url: str) -> None:
        self.engine = create_engine(
            database_url,
            future=True,
            pool_pre_ping=True,
            pool_recycle=280,
        )
        self.metadata = MetaData()
        self.titles = Table(
            "titles",
            self.metadata,
            Column("id", Integer, primary_key=True, autoincrement=True),
            Column("name", String(160), nullable=False),
            Column("genre", String(80), nullable=False),
            Column("year", Integer, nullable=False),
            Column("rating", String(20), nullable=False),
            Column("synopsis", Text, nullable=False),
            Column("accent", String(30), nullable=False),
        )
        self.reviews = Table(
            "reviews",
            self.metadata,
            Column("id", Integer, primary_key=True, autoincrement=True),
            Column("title_id", Integer, nullable=False),
            Column("nickname", String(80), nullable=False),
            Column("body", Text, nullable=False),
            Column("status", String(30), nullable=False, default="pending"),
        )
        self.users = Table(
            "users",
            self.metadata,
            Column("id", Integer, primary_key=True, autoincrement=True),
            Column("username", String(80), nullable=False, unique=True),
            # INTENTIONALLY WEAK: fake lab passwords only. Never copy this design.
            Column("password", String(160), nullable=False),
            Column("role", String(30), nullable=False),
        )
        self.subscribers = Table(
            "subscribers",
            self.metadata,
            Column("id", Integer, primary_key=True, autoincrement=True),
            Column("user_id", Integer, nullable=True),
            Column("full_name", String(80), nullable=False),
            Column("email", String(160), nullable=False),
            Column("plan", String(40), nullable=False),
            Column("payment_last4", String(4), nullable=False),
            Column("status", String(30), nullable=False),
        )
        self.lab_flags = Table(
            "lab_flags",
            self.metadata,
            Column("id", Integer, primary_key=True, autoincrement=True),
            Column("flag_name", String(80), nullable=False, unique=True),
            Column("flag_value", String(200), nullable=False),
        )

    def initialize(self) -> None:
        self.metadata.create_all(self.engine)
        with self.engine.begin() as connection:
            if connection.execute(select(self.titles.c.id)).first() is None:
                connection.execute(self.titles.insert(), _SEED_TITLES)
            if connection.execute(select(self.users.c.id)).first() is None:
                connection.execute(self.users.insert(), _SEED_USERS)
            if connection.execute(select(self.subscribers.c.id)).first() is None:
                connection.execute(self.subscribers.insert(), _SEED_SUBSCRIBERS)
            if connection.execute(select(self.lab_flags.c.id)).first() is None:
                connection.execute(self.lab_flags.insert(), _SEED_FLAGS)

    def featured_titles(self) -> list[dict]:
        with self.engine.connect() as connection:
            rows = connection.execute(
                select(self.titles).order_by(self.titles.c.id).limit(6)
            ).mappings()
            return [dict(row) for row in rows]

    def search_titles_vulnerable(self, query: str) -> tuple[list[dict], str | None]:
        # INTENTIONALLY VULNERABLE: scanner training target.
        sql = (
            "SELECT id, name, genre, year, rating, synopsis, accent FROM titles "
            f"WHERE name LIKE '%{query}%' OR genre LIKE '%{query}%' ORDER BY id"
        )
        try:
            with self.engine.connect() as connection:
                rows = connection.execute(text(sql)).mappings()
                return [dict(row) for row in rows], None
        except Exception as exc:  # Error disclosure is intentional in this lab.
            return [], str(exc)

    def authenticate_vulnerable(self, username: str, password: str) -> dict | None:
        # INTENTIONALLY VULNERABLE: raw string interpolation for scanner training.
        sql = (
            "SELECT id, username, role FROM users "
            f"WHERE username = '{username}' AND password = '{password}' LIMIT 1"
        )
        try:
            with self.engine.connect() as connection:
                row = connection.execute(text(sql)).mappings().first()
                return dict(row) if row else None
        except Exception:
            return None

    def subscriber_for_user(self, user_id: int) -> dict | None:
        with self.engine.connect() as connection:
            row = connection.execute(
                select(self.subscribers).where(self.subscribers.c.user_id == user_id)
            ).mappings().first()
            return dict(row) if row else None

    def subscriber_count(self) -> int:
        with self.engine.connect() as connection:
            return int(
                connection.execute(
                    select(func.count()).select_from(self.subscribers)
                ).scalar_one()
            )

    def lab_flag_value(self, flag_name: str) -> str | None:
        with self.engine.connect() as connection:
            return connection.execute(
                select(self.lab_flags.c.flag_value).where(
                    self.lab_flags.c.flag_name == flag_name
                )
            ).scalar_one_or_none()

    def get_title(self, title_id: int) -> dict | None:
        with self.engine.connect() as connection:
            row = connection.execute(
                select(self.titles).where(self.titles.c.id == title_id)
            ).mappings().first()
            return dict(row) if row else None

    def add_review(self, title_id: int, nickname: str, body: str) -> None:
        with self.engine.begin() as connection:
            connection.execute(
                self.reviews.insert(),
                {
                    "title_id": title_id,
                    "nickname": nickname or "anonymous",
                    "body": body,
                    "status": "pending",
                },
            )

    def reviews_for_title(self, title_id: int) -> list[dict]:
        with self.engine.connect() as connection:
            rows = connection.execute(
                select(self.reviews)
                .where(self.reviews.c.title_id == title_id)
                .order_by(self.reviews.c.id.desc())
            ).mappings()
            return [dict(row) for row in rows]

    def all_reviews(self) -> list[dict]:
        statement = (
            select(
                self.reviews.c.id,
                self.reviews.c.nickname,
                self.reviews.c.body,
                self.reviews.c.status,
                self.titles.c.name.label("title_name"),
            )
            .join(self.titles, self.reviews.c.title_id == self.titles.c.id)
            .order_by(self.reviews.c.id.desc())
        )
        with self.engine.connect() as connection:
            return [dict(row) for row in connection.execute(statement).mappings()]

    def title_count(self) -> int:
        with self.engine.connect() as connection:
            return int(connection.execute(select(func.count()).select_from(self.titles)).scalar_one())

    def review_count(self) -> int:
        with self.engine.connect() as connection:
            return int(connection.execute(select(func.count()).select_from(self.reviews)).scalar_one())

    def clear_reviews(self) -> None:
        with self.engine.begin() as connection:
            connection.execute(self.reviews.delete())


_SEED_TITLES = [
    {
        "name": "우주의 경계",
        "genre": "SF · 미스터리",
        "year": 2026,
        "rating": "15+",
        "synopsis": "태양계 끝에서 발견된 신호를 추적하는 탐사대의 기록.",
        "accent": "violet",
    },
    {
        "name": "마지막 신호",
        "genre": "스릴러",
        "year": 2025,
        "rating": "15+",
        "synopsis": "도시 전체의 통신이 끊기기 전 도착한 하나의 메시지.",
        "accent": "cyan",
    },
    {
        "name": "붉은 행성",
        "genre": "SF · 드라마",
        "year": 2024,
        "rating": "12+",
        "synopsis": "화성 개척지에서 살아남은 사람들의 선택과 연대.",
        "accent": "red",
    },
    {
        "name": "잊힌 도시",
        "genre": "어드벤처",
        "year": 2026,
        "rating": "12+",
        "synopsis": "지도에서 사라진 도시를 찾아 나선 기록 보관가의 여정.",
        "accent": "amber",
    },
    {
        "name": "심해의 기록",
        "genre": "다큐멘터리",
        "year": 2025,
        "rating": "ALL",
        "synopsis": "빛이 닿지 않는 바다에서 만난 생명과 미지의 풍경.",
        "accent": "blue",
    },
    {
        "name": "시간의 문",
        "genre": "판타지",
        "year": 2023,
        "rating": "12+",
        "synopsis": "매일 자정 단 한 번 열리는 문 너머의 세계.",
        "accent": "green",
    },
]

_SEED_USERS = [
    {
        "id": 1,
        "username": "admin",
        "password": "admin123",
        "role": "admin",
    },
    {
        "id": 2,
        "username": "viewer",
        "password": "viewer123",
        "role": "user",
    },
]

_SEED_SUBSCRIBERS = [
    {
        "user_id": 2,
        "full_name": "김노바",
        "email": "nova01@example.test",
        "plan": "Premium",
        "payment_last4": "4821",
        "status": "active",
    },
    {
        "user_id": None,
        "full_name": "이스트림",
        "email": "stream02@example.test",
        "plan": "Basic",
        "payment_last4": "1937",
        "status": "active",
    },
    {
        "user_id": None,
        "full_name": "박시청",
        "email": "viewer03@example.test",
        "plan": "Standard",
        "payment_last4": "7504",
        "status": "suspended",
    },
]

_SEED_FLAGS = [
    {
        "flag_name": "sqli_extraction",
        "flag_value": "FLAG{NOVASTREAM_SQLI_EXTRACTION_SUCCESS}",
    }
]
