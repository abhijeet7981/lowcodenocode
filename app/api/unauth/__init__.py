from flask import current_app, g, Blueprint, request
import base64
import json

unAuth = Blueprint('unAuth', __name__)


@unAuth.before_request
def before_request():
    pass
