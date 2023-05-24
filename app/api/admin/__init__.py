from flask import current_app, g, Blueprint, request
import base64
import json

admin_app_api = Blueprint('admin_app_api', __name__)


@admin_app_api.before_request
def before_request():
    pass
