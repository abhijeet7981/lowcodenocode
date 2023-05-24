import pymysql
import os
from dotenv import load_dotenv, find_dotenv
from pymysql import cursors

load_dotenv(find_dotenv("config/.env"))


def connect():
    try:
        # To connect MySQL database
        conn = pymysql.connect(
            host=os.environ.get('HOST'),
            user=os.environ.get('DBUSER'),
            password=os.environ.get('PASSWORD'),
            db=os.environ.get('CLASSROOM_DB'),
            cursorclass=pymysql.cursors.DictCursor
        )
        return conn
    except Exception as reason:
        return reason
