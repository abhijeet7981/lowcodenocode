import os
import uuid
from pymysql import IntegrityError
import dotenv
import openai
from flask import render_template, request, make_response
from flask_cors import cross_origin
import collections
from collections import abc
from app.api.unauth import unAuth
from db.databaseConnect import connect
from app.api.unauth import query
import bcrypt
from common_package import custom
from flask_jwt_extended import create_access_token
from flask_jwt_extended import create_refresh_token
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
import base64


collections.Iterable = collections.abc.Iterable
dotenv.load_dotenv("config/.env")


@unAuth.route('/get-tasks-status', methods=['GET'])
@cross_origin()
def get_tasks_status():
    db = connect()
    try:
        cursorObject = db.cursor()
        cursorObject.execute(query.getTasksStatus.format())
        data = cursorObject.fetchall()
        return make_response(
            {"status": True,
             "message": "Success",
             "data": data}, 200)

    except Exception as e:
        return make_response({"status": False,
                              "message": "Something went wrong"}, 500)


@unAuth.route('/get-tasks-priority', methods=['GET'])
@cross_origin()
def get_tasks_priority():
    db = connect()
    try:
        cursorObject = db.cursor()
        cursorObject.execute(query.getTasksPriority.format())
        data = cursorObject.fetchall()
        return make_response(
            {"status": True,
             "message": "Success",
             "data": data}, 200)

    except Exception as e:
        return make_response({"status": False,
                              "message": "Something went wrong"}, 500)

