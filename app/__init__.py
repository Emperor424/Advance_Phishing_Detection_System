from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_mail import Mail
from flask_wtf.csrf import CSRFProtect
from config import config

db            = SQLAlchemy()
login_manager = LoginManager()
mail          = Mail()
csrf          = CSRFProtect()


def create_app(config_name="default"):
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(config[config_name])

    db.init_app(app)
    login_manager.init_app(app)
    mail.init_app(app)
    csrf.init_app(app)

    login_manager.login_view             = "auth.login"
    login_manager.login_message          = "Please log in to access this page."
    login_manager.login_message_category = "warning"

    from app.models.user import User

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    # Blueprints
    from app.routes.auth         import auth_bp
    from app.routes.email_routes import email_bp
    from app.routes.admin        import admin_bp
    from app.routes.quarantine   import quarantine_bp
    from app.routes.email_api    import api_bp

    app.register_blueprint(auth_bp,       url_prefix="/auth")
    app.register_blueprint(email_bp,      url_prefix="/email")
    app.register_blueprint(admin_bp,      url_prefix="/admin")
    app.register_blueprint(quarantine_bp, url_prefix="/quarantine")
    app.register_blueprint(api_bp,        url_prefix="/api")

    from flask import redirect, url_for

    @app.route("/")
    def index():
        return redirect(url_for("auth.login"))

    with app.app_context():
        db.create_all()

    return app
