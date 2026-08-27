"""Flask training application entry point."""

import time as _time

from flask import Flask, jsonify, request


def create_app() -> Flask:
    app = Flask(__name__)

    @app.get("/health")
    def health() -> tuple[object, int]:
        return jsonify(status="ok"), 200

    @app.get("/case/sqli-a")
    def temp_case_sqli_a():
        """임시 자체 테스트용 가짜 취약 페이지.
        1팀이 실제 SQLi 페이지를 만들면 이 함수는 삭제하세요.
        """
        value = request.args.get("id", "")
        lowered = value.lower()

        if "sleep(5)" in lowered:
            _time.sleep(5)
            return "ok", 200
        if "1=1" in lowered:
            return "검색 결과 3건: laptop, phone, keyboard", 200
        if "1=2" in lowered:
            return "검색 결과 0건", 200
        if "'" in value and any(k in lowered for k in ["union", "select", "or '1'='1", "drop table", "convert"]):
            return f"Error: You have an error in your SQL syntax near '{value}'", 500
        return f"검색 결과: '{value}' 에 대한 상품이 없습니다.", 200

    @app.post("/case/sqli-login")
    def temp_case_sqli_login():
        """임시 자체 테스트용 가짜 로그인 페이지 (인증 우회 신호 검증용).
        1팀이 실제 로그인 페이지를 만들면 이 함수는 삭제하세요.
        """
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        if "' or '1'='1" in username.lower() or "admin'--" in username.lower():
            return "로그인 성공! 환영합니다.", 200
        if username == "admin" and password == "correct-password":
            return "로그인 성공! 환영합니다.", 200
        return "로그인 실패: 아이디 또는 비밀번호가 올바르지 않습니다.", 401

    return app


app = create_app()