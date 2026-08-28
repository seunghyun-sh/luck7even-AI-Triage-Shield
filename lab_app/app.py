"""Lumi Market application factory.

This app intentionally contains XSS and SQL injection flaws for the team's
authorized, isolated training environment.
"""

import os
from pathlib import Path

from flask import Flask, render_template

from lab_app.db import close_db, init_db, reset_db
from lab_app.routes.auth import auth_bp
from lab_app.routes.community import community_bp
from lab_app.routes.lab import lab_bp
from lab_app.routes.storefront import storefront_bp


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__)
    app.config.from_mapping(
        DATABASE=str(Path(app.root_path) / "instance" / "lumi_market_1.sqlite3"),
        DB_ENGINE=os.getenv("LAB_1_DB_ENGINE", "sqlite").lower(),
        DB_HOST=os.getenv("LAB_1_DB_HOST", "127.0.0.1"),
        DB_PORT=int(os.getenv("LAB_1_DB_PORT", "3306")),
        DB_NAME=os.getenv("LAB_1_DB_NAME", "lumi_market_1"),
        DB_USER=os.getenv("LAB_1_DB_USER", "lumi_app_1"),
        DB_PASSWORD=os.getenv("LAB_1_DB_PASSWORD", ""),
        DB_CONNECT_TIMEOUT=int(os.getenv("LAB_1_DB_CONNECT_TIMEOUT", "5")),
        SECRET_KEY=os.getenv("LAB_1_SECRET_KEY", "local-training-session-key-1"),
        LAB_1_RESET_TOKEN=os.getenv("LAB_1_RESET_TOKEN", ""),
        LAB_1_SECURITY_MODE=os.getenv(
            "LAB_1_SECURITY_MODE", "vulnerable"
        ).lower(),
    )

    if test_config:
        app.config.update(test_config)

    if app.config["DB_ENGINE"] == "sqlite":
        Path(app.config["DATABASE"]).parent.mkdir(parents=True, exist_ok=True)
    app.teardown_appcontext(close_db)
    app.cli.command("init-db")(init_db)
    app.cli.command("reset-db")(reset_db)

    if (
        app.config["DB_ENGINE"] == "sqlite"
        and not Path(app.config["DATABASE"]).exists()
    ):
        with app.app_context():
            init_db()

    app.register_blueprint(storefront_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(community_bp)
    app.register_blueprint(lab_bp)

    @app.errorhandler(404)
    def not_found(_error):
        return render_template("404.html"), 404

    return app


app = create_app()


if __name__ == "__main__":
    app.run(
        host=os.getenv("LAB_1_HOST", "127.0.0.1"),
        port=int(os.getenv("LAB_1_PORT", "5001")),
        debug=False,
    )
