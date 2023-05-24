from flask import current_app, g, Blueprint, request
import base64
import json

app_api = Blueprint('app_api', __name__)


@app_api.before_request
def before_request():
    pass
