"""NovaStream Flask application factory."""

from __future__ import annotations

import os
from functools import wraps

from flask import Flask, redirect, render_template, request, session, url_for

from .db import Database


def weak_sql_filter(value: str) -> str | None:
    """Return the first token blocked by the intentionally weak SQL filter."""
    for blocked in (" ", "UNION", "SELECT"):
        if blocked in value:
            return "일반 공백" if blocked == " " else blocked
    return None


def weak_xss_filter(value: str) -> str:
    """One-pass, case-sensitive removal used only for scanner training."""
    return value.replace("script", "")


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__)
    app.config.from_mapping(
        DATABASE_URL=os.getenv("LAB2_DATABASE_URL", "sqlite:///lab_app_2/novastream.db"),
        SECRET_KEY=os.getenv("LAB2_SECRET_KEY", "novastream-local-lab-only"),
    )
    if test_config:
        app.config.update(test_config)

    database = Database(app.config["DATABASE_URL"])
    database.initialize()
    app.extensions["novastream_db"] = database

    def login_required(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if "user_id" not in session:
                return redirect(url_for("login"))
            return view(*args, **kwargs)

        return wrapped

    def admin_required(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if session.get("role") != "admin":
                return redirect(url_for("login"))
            return view(*args, **kwargs)

        return wrapped

    @app.get("/")
    def index():
        return render_template("index.html", titles=database.featured_titles())

    @app.get("/catalog")
    def catalog():
        query = request.args.get("q", "")
        titles = database.featured_titles()
        error = None
        filter_message = None
        if query:
            blocked = weak_sql_filter(query)
            if blocked:
                titles = []
                filter_message = f"요청이 보안 필터에 의해 차단되었습니다: {blocked}"
            else:
                titles, error = database.search_titles_vulnerable(query)
        return render_template(
            "catalog.html",
            query=query,
            titles=titles,
            error=error,
            filter_message=filter_message,
        )

    @app.get("/discover")
    def discover():
        query = request.args.get("q", "")
        filtered_query = weak_xss_filter(query)
        return render_template(
            "discover.html", query=query, filtered_query=filtered_query
        )

    @app.route("/login", methods=["GET", "POST"])
    def login():
        error = None
        username = ""
        if request.method == "POST":
            username = request.form.get("username", "")
            password = request.form.get("password", "")
            blocked = weak_sql_filter(username) or weak_sql_filter(password)
            if blocked:
                error = f"요청이 보안 필터에 의해 차단되었습니다: {blocked}"
            else:
                user = database.authenticate_vulnerable(username, password)
                if user:
                    session.clear()
                    session["user_id"] = user["id"]
                    session["username"] = user["username"]
                    session["role"] = user["role"]
                    if user["role"] == "admin":
                        return redirect(url_for("admin_dashboard"))
                    return redirect(url_for("index"))
                error = "아이디 또는 비밀번호가 올바르지 않습니다."
        return render_template("login.html", error=error, username=username)

    @app.get("/logout")
    def logout():
        session.clear()
        return redirect(url_for("index"))

    @app.get("/account")
    @login_required
    def account():
        subscriber = database.subscriber_for_user(int(session["user_id"]))
        return render_template("account.html", subscriber=subscriber)

    @app.get("/titles/<int:title_id>")
    def title_detail(title_id: int):
        title = database.get_title(title_id)
        if title is None:
            return render_template("not_found.html"), 404
        return render_template(
            "title_detail.html",
            title=title,
            reviews=database.reviews_for_title(title_id),
        )

    @app.post("/titles/<int:title_id>/reviews")
    def add_review(title_id: int):
        if database.get_title(title_id) is None:
            return render_template("not_found.html"), 404
        database.add_review(
            title_id=title_id,
            nickname=request.form.get("nickname", "anonymous"),
            body=weak_xss_filter(request.form.get("body", "")),
        )
        return redirect(url_for("title_detail", title_id=title_id, saved="1"))

    @app.get("/admin")
    @admin_required
    def admin_dashboard():
        return render_template(
            "admin_dashboard.html",
            title_count=database.title_count(),
            review_count=database.review_count(),
        )

    @app.get("/admin/reviews")
    @admin_required
    def admin_reviews():
        return render_template("admin_reviews.html", reviews=database.all_reviews())

    @app.post("/admin/reviews/clear")
    @admin_required
    def clear_reviews():
        database.clear_reviews()
        return redirect(url_for("admin_reviews"))

    @app.get("/health")
    def health():
        return {"service": "novastream", "status": "ok"}

    return app


if __name__ == "__main__":
    create_app().run(
        host=os.getenv("LAB2_HOST", "127.0.0.1"),
        port=int(os.getenv("LAB2_PORT", "5000")),
        debug=False,
    )
