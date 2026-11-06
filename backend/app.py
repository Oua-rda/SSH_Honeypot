from flask import Flask, jsonify

from backend.routes import ApiError, bp
from database.db import DEFAULT_DB, init_db


def create_app(db_path=DEFAULT_DB) -> Flask:
    app = Flask(__name__,
                template_folder="../dashboard/templates",
                static_folder="../dashboard/static")
    app.config["DB_PATH"] = db_path
    init_db(db_path)
    app.register_blueprint(bp)

    @app.errorhandler(ApiError)
    def api_error(e):
        return jsonify(error=e.message), e.status

    @app.errorhandler(404)
    def not_found(_):
        return jsonify(error="not found"), 404

    @app.errorhandler(500)
    def server_error(_):
        return jsonify(error="internal server error"), 500

    @app.after_request
    def security_headers(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Cache-Control"] = "no-store"
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self' data:; frame-ancestors 'none'")
        return resp

    return app


if __name__ == "__main__":
    # 127.0.0.1 = reachable only from this machine. debug stays OFF on purpose.
    create_app().run(host="127.0.0.1", port=5000, debug=False)