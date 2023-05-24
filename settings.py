import datetime
import os
from datetime import timedelta
from collections import defaultdict
from botocore.config import Config
import boto3


class DevConfig:
    """
    Developer: Anirban Dutta
    Project Name: Low code No Code
    Developer Email: anirban.d@utahtechlab.com
    Env: Development
    """
    ENV = "development"
    DEBUG = True
    CACHE_TYPE = "SimpleCache",  # Flask-Caching related configs
    CACHE_DEFAULT_TIMEOUT = 300
    SECRET_KEY = os.getenv('SECRET_KEY') or os.urandom(32)
    ITEMS_PER_PAGE = 20
    PAGINATION_PER_PAGE = 10
    UPLOAD_FOLDER = "supportFile/"
    JWT_AUTH_URL_RULE = '/login'
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(days=1)
    JWT_EXPIRATION_DELTA = timedelta(hours=10)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=2)
    MY_ENV_VAR = os.getenv('SENDGRID_API_KEY')
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY') or os.urandom(32)
    s3 = boto3.client('s3', region_name=os.getenv('REGION'),
                      aws_access_key_id=os.getenv('AWS_ACCESS_KEY'),
                      aws_secret_access_key=os.getenv("AWS_SECRET_KEY"),
                      config=Config(signature_version='s3v4'))
    bucket_name = 'lowcodedev'
    valid_admin_email = "anirban.d@utahtechlab.com"
    sender_email = "info@futurework.land"
    open_api_key = os.getenv('OPENAI_API_KEY')
    BACKEND_URL = "https://lowcodeapi.futurework.land/"
    FRONTEND_URL = "https://lowcode.futurework.land/"

    @staticmethod
    def init_app(app):
        pass
