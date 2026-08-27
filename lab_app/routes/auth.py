"""Account pages, including the intentional SQL injection target."""

import sqlite3

from flask import Blueprint, redirect, render_template, request, session, url_for

from lab_app.db import get_db

auth_bp = Blueprint("auth", __name__, url_prefix="/account")


@auth_bp.route("/login", methods=("GET", "POST"))
def login():
    error = None
    sql_error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        # Intentionally vulnerable: raw form input is concatenated into SQL.
        query = (
            "SELECT id, username, display_name, email, role FROM users "
            f"WHERE username = '{username}' AND password = '{password}'"
        )
        try:
            user = get_db().execute(query).fetchone()
        except sqlite3.Error as exc:
            user = None
            sql_error = str(exc)
        if user:
            session.clear()
            session["user"] = dict(user)
            return redirect(url_for("auth.profile"))
        error = "아이디 또는 비밀번호를 확인해 주세요."
    return render_template("login.html", error=error, sql_error=sql_error)


@auth_bp.route("/register", methods=("GET", "POST"))
def register():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        display_name = request.form.get("display_name", "").strip()
        email = request.form.get("email", "").strip()
        if not all((username, password, display_name, email)):
            error = "모든 항목을 입력해 주세요."
        else:
            try:
                db = get_db()
                db.execute(
                    "INSERT INTO users (username, password, display_name, email) "
                    "VALUES (?, ?, ?, ?)",
                    (username, password, display_name, email),
                )
                db.commit()
                return redirect(url_for("auth.login"))
            except sqlite3.IntegrityError:
                error = "이미 사용 중인 아이디입니다."
    return render_template("register.html", error=error)


@auth_bp.get("")
def profile():
    user = session.get("user")
    if user is None:
        return redirect(url_for("auth.login"))
    return render_template("profile.html", user=user)


@auth_bp.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("storefront.home"))

