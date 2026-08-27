"""NovaStream Flask application factory."""

from __future__ import annotations

import os

from flask import Flask, redirect, render_template, request, url_for

from .db import Database


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

    @app.get("/")
    def index():
        return render_template("index.html", titles=database.featured_titles())

    @app.get("/catalog")
    def catalog():
        query = request.args.get("q", "")
        titles = database.featured_titles()
        error = None
        if query:
            titles, error = database.search_titles_vulnerable(query)
        return render_template("catalog.html", query=query, titles=titles, error=error)

    @app.get("/discover")
    def discover():
        query = request.args.get("q", "")
        return render_template("discover.html", query=query)

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
            body=request.form.get("body", ""),
        )
        return redirect(url_for("title_detail", title_id=title_id, saved="1"))

    @app.get("/admin")
    def admin_dashboard():
        return render_template(
            "admin_dashboard.html",
            title_count=database.title_count(),
            review_count=database.review_count(),
        )

    @app.get("/admin/reviews")
    def admin_reviews():
        return render_template("admin_reviews.html", reviews=database.all_reviews())

    @app.post("/admin/reviews/clear")
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
