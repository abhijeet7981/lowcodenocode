import os
from datetime import timedelta
from flask import Flask, request
from flask_jwt_extended import JWTManager
from app.api.users.views import app_api
from app.api.admin.views import admin_app_api
from app.api.unauth.views import unAuth
import logging
from logging.handlers import RotatingFileHandler
from settings import DevConfig

app = Flask(__name__)
# app.config["SECRET_KEY"] = os.getenv('SECRET_KEY') or os.urandom(32)
app.config["SECRET_KEY"] = DevConfig.SECRET_KEY
# app.permanent_session_lifetime = timedelta(minutes=60)
# app.config['UPLOAD_FOLDER'] = "supportFile/"
app.config['UPLOAD_FOLDER'] = DevConfig.UPLOAD_FOLDER
# app.config['JWT_AUTH_URL_RULE'] = '/login'
app.config['JWT_AUTH_URL_RULE'] = DevConfig.JWT_AUTH_URL_RULE
# jwt_manager = JWTManager(app)
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = DevConfig.JWT_ACCESS_TOKEN_EXPIRES
app.config['JWT_EXPIRATION_DELTA'] = DevConfig.JWT_EXPIRATION_DELTA
app.config["JWT_REFRESH_TOKEN_EXPIRES"] = DevConfig.JWT_REFRESH_TOKEN_EXPIRES
jwt = JWTManager(app)
MY_ENV_VAR = DevConfig.MY_ENV_VAR
app.config["JWT_SECRET_KEY"] = DevConfig.JWT_SECRET_KEY
app.config['PROPAGATE_EXCEPTIONS'] = True


app.register_blueprint(admin_app_api)
app.register_blueprint(app_api)
app.register_blueprint(unAuth)


debug_handler = RotatingFileHandler('appLog/debug.log', maxBytes=10000, backupCount=1)
debug_handler.setLevel(logging.DEBUG)
app.logger.addHandler(debug_handler)

info_handler = RotatingFileHandler('appLog/info.log', maxBytes=10000, backupCount=1)
info_handler.setLevel(logging.INFO)
app.logger.addHandler(info_handler)

warning_handler = RotatingFileHandler('appLog/warning.log', maxBytes=10000, backupCount=1)
warning_handler.setLevel(logging.WARNING)
app.logger.addHandler(warning_handler)

error_handler = RotatingFileHandler('appLog/error.log', maxBytes=10000, backupCount=1)
error_handler.setLevel(logging.ERROR)
app.logger.addHandler(error_handler)

critical_handler = RotatingFileHandler('appLog/critical.log', maxBytes=10000, backupCount=1)
critical_handler.setLevel(logging.CRITICAL)
app.logger.addHandler(critical_handler)


@app.after_request
def index(response):
    api_name = request.url_rule.rule if request.url_rule else "Unknown"
    app.logger.info('%s %s %s %s %s', request.remote_addr, request.method, api_name,
                    response.status, response.content_length)
    return response


if __name__ == "__main__":
    app.run(debug=True, port=9000, host='0.0.0.0')
