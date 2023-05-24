import datetime
import os
import uuid
from datetime import timedelta
from collections import defaultdict
from botocore.config import Config
from pymysql import IntegrityError
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
import dotenv
import openai
from flask import render_template, request, make_response
from flask_cors import cross_origin
import collections
from collections import abc
from app.api.users import app_api
from db.databaseConnect import connect
from app.api.users import query
import bcrypt
from common_package import custom
from flask_jwt_extended import create_access_token
from flask_jwt_extended import create_refresh_token
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
import base64
import boto3
from settings import DevConfig


collections.Iterable = collections.abc.Iterable
dotenv.load_dotenv("config/.env")
# openai.api_key = os.getenv('OPENAI_API_KEY')
# valid_admin_email = "anirban.d@utahtechlab.com"
# sender_email = "info@futurework.land"
# s3 = boto3.client('s3', region_name=os.getenv('REGION'),
#                   aws_access_key_id=os.getenv('AWS_ACCESS_KEY'),
#                   aws_secret_access_key=os.getenv("AWS_SECRET_KEY"), config=Config(signature_version='s3v4'))

openai.api_key = DevConfig.open_api_key
s3 = DevConfig.s3
sender_email = DevConfig.sender_email
valid_admin_email = DevConfig.valid_admin_email


@app_api.route('/', methods=['GET'])
@cross_origin()
def home():
    return make_response({"status": True, "msg": "welcome"})


@app_api.route('/send-user-email', methods=["POST", "GET"])
@cross_origin()
def sent_user_email():
    try:
        email = request.json.get('email')
        isAdminAdded = int(request.json.get('isAdminAdded'))
        if not email:
            return make_response({"status": False,
                                  "message": "Missing user Email"}, 400)

        db = connect()
        cursorObject = db.cursor()
        cursorObject.execute(query.userEmailExist.format(email=email))
        fetch = cursorObject.fetchone()
        passwordByUser = fetch["password"]
        userFullName = fetch['name']
        adminCreated = fetch['admin_id']
        getAccessLevel = fetch['access_level']
        data_encrypted = passwordByUser.strip("b")
        data_encrypted = data_encrypted.replace("'", "")
        # print(data_encrypted)
        decode = base64.b64decode(data_encrypted)
        data_decode = bytes(decode).decode('utf-8')
        # print(data_decode)
        cursorObject.execute(query.getAdminCompanyByID.format(admin_id=adminCreated))
        getDetailsCompany = cursorObject.fetchone()
        # print(getDetailsCompany)
        companyName = getDetailsCompany['company_name']
        cursorObject.execute(query.getUserAccessLevelValue.format(access_level=getAccessLevel))
        getAccessLevelValue = cursorObject.fetchone()
        # print(getAccessLevelValue)
        getValueAccess = getAccessLevelValue['access_level_name']
        oneTimePassword = custom.generate_otp()
        oneTimePassword = str(oneTimePassword)
        # print(oneTimePassword)
        hashed = bcrypt.hashpw(oneTimePassword.encode('utf-8'), bcrypt.gensalt())
        cursorObject.execute(query.userAddOtp.format(email=email, temp_code=hashed))
        db.commit()
        if isAdminAdded == 1:
            message = Mail(
                from_email=sender_email,
                to_emails=[email],
                subject=f'Invitation from {companyName}',
                html_content=render_template('send_user_verification_email.html',
                                             companyName=companyName, name=userFullName,
                                             getValueAccess=getValueAccess, passwordByUser=data_decode))
            sg = SendGridAPIClient(os.environ.get('SENDGRID_API_KEY'))
            sg.send(message)
            return make_response({"status": True,
                                  "code": 200,
                                  "message": f"Mail has been sent to {email}. Please check your inbox."}, 200)
        elif isAdminAdded == 0:
            message = Mail(
                from_email=sender_email,
                to_emails=[email],
                subject='OTP from Admin',
                html_content=render_template('send_user_verification_0.html',
                                             oneTimePassword=oneTimePassword, userFullName=userFullName,
                                             passwordByUser=data_decode))
            sg = SendGridAPIClient(os.environ.get('SENDGRID_API_KEY'))
            sg.send(message)
            return make_response({"status": True,
                                  "code": 200,
                                  "message": f"Mail has been sent to {email}. Please check your inbox."}, 200)

    except:
        return make_response({"status": False,
                              "message": "Something went wrong."}, 500)


@app_api.route('/validate-user-email', methods=["POST"])
@cross_origin()
def validate_user_email():
    try:
        email = request.json.get('email')
        otp = request.json.get('otp')
        password = request.json.get('password')
        new_password = request.json.get('new_password')

        if not email:
            return make_response({"status": False,
                                  "message": "Missing user Email"}, 400)
        if not otp:
            return make_response({"status": False,
                                  "message": "Missing is user OTP"}, 400)
        if not password:
            return make_response({"status": False,
                                  "message": "Missing is user password"}, 400)
        if not new_password:
            return make_response({"status": False,
                                  "message": "Missing is user new password"}, 400)
        if len(new_password) < 8:
            return make_response({"status": False,
                                  "message": "Error, Length must must be more than 8 characters"}, 400)

        userEnterOtp = otp.encode("utf-8")
        db = connect()
        cursorObject = db.cursor()
        cursorObject.execute(query.userEmailExist.format(email=email))
        fetch = cursorObject.fetchone()
        checkEmail = fetch['email']
        temp_code_get = fetch["temp_code"].strip("b")
        temp_code_get = temp_code_get.replace("'", "")
        temp_code_get = temp_code_get.encode("utf-8")
        passwordByUser = fetch['password']
        data_encrypted = passwordByUser.strip("b")
        data_encrypted = data_encrypted.replace("'", "")
        # print(data_encrypted)
        decode = base64.b64decode(data_encrypted)
        data_decode = bytes(decode).decode('utf-8')
        # print(data_decode)
        if bcrypt.checkpw(userEnterOtp, temp_code_get) and email == fetch["email"]:
            is_verified = 1
            cursorObject.execute(query.verifyUser.format(email=email, is_verified=is_verified))
            db.commit()
            if password == data_decode:
                hashed = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
                cursorObject.execute(query.updateUserPassword.format(email=email, password=hashed))
                db.commit()
                return make_response({"status": True,
                                      "code": 200,
                                      "message": "Email  verification is  successful."}, 200)
            else:
                return make_response({"status": False,
                                      "message": "Failure, password doesnt match."}, 200)
        else:
            return make_response({"status": False,
                                  "message": "Failure, OTP does not match."}, 200)
    except:
        return make_response({"status": False,
                              "message": "Something went wrong."}, 500)


@app_api.route('/user-login', methods=['POST'])
@cross_origin()
def user_login():
    db = connect()
    try:
        userEmail = request.json.get('email')
        userPassword = request.json.get('password')

        if not userEmail:
            return make_response({"status": False,
                                  "message": "Missing email"}, 400)
        if not userPassword:
            return make_response({"status": False,
                                  "message": "Missing Password"}, 400)

        userEnterPassword = userPassword.encode("utf-8")
        cursorObject = db.cursor()
        cursorObject.execute(query.userEmailExist.format(email=userEmail))
        fetch = cursorObject.fetchone()
        # print(fetch)
        try:
            userID = fetch["user_id"]
            isUserVerified = fetch["is_verified"]
            userAccessLevel = fetch['access_level']
            userFullName = fetch['name']
            companyName = fetch['company_name']
            is_deleted = fetch['is_deleted']
            checkBanned = fetch['is_banned']
            # accountType = fetch['accountType']
            # userDepartment = fetch['userDepartment']
            # grade_levelID = fetch['grade_levelID']
            if checkBanned == 0:
                if is_deleted == 0:
                    if isUserVerified == 1:
                        # print(adminID)
                        passwordByUser = fetch["password"].strip("b")
                        passwordByUser = passwordByUser.replace("'", "")
                        passwordByUser = passwordByUser.encode("utf-8")
                        db.commit()
                        # db.close()
                        if bcrypt.checkpw(userEnterPassword, passwordByUser) and userEmail == fetch["email"]:
                            # print("HI")
                            # session['logged_in'] = True
                            access_token = create_access_token(identity=userEmail)
                            refresh_token = create_refresh_token(identity=userEmail)
                            data = {"user_id": userID,
                                    "access_token": access_token,
                                    "refresh_token": refresh_token,
                                    "access_level": userAccessLevel,
                                    "name": userFullName,
                                    "company_name": companyName}
                            return make_response({"status": True,
                                                  "code": 200,
                                                  'message': "Login Succeeded!",
                                                  "data": data}, 200)
                        else:
                            return make_response({"message": "Login failed, Incorrect Email or Password",
                                                  "status": False}, 200)
                    elif isUserVerified == 0:
                        return make_response({"status": False,
                                              "message": "Email verification pending"}, 200)
                else:
                    return make_response({"status": False,
                                          "message": "Login failed, Incorrect Email or Password"}, 200)
            else:
                return make_response({"status": False,
                                      "message": "Login failed. Contact Admin for help"}, 200)
        except Exception as e:
            return make_response({"status": False,
                                  "message": "Login failed, Incorrect Email or Password"}, 200)
    except AttributeError:
        return make_response({"status": False,
                              "message": 'Provide an Email and Password in JSON format in the request body'}, 400)


@app_api.route('/forgot-password', methods=['POST'])
@cross_origin()
def user_forgotPassword():
    db = connect()
    try:
        email = request.json.get('email', None)

        if not email:
            return make_response({"status": False,
                                  "message": "Missing email"}, 400)

        cursorObject = db.cursor()
        cursorObject.execute(query.userEmailExist.format(email=email))
        fetch = cursorObject.fetchone()
        try:
            is_verified = fetch["is_verified"]
            email = fetch['email']
            if is_verified == 1:
                oneTimePassword = custom.generate_otp()
                oneTimePassword = str(oneTimePassword)
                hashed = bcrypt.hashpw(oneTimePassword.encode('utf-8'), bcrypt.gensalt())
                cursorObject.execute(query.userAddOtp.format(email=email, temp_code=hashed))
                db.commit()
                message = Mail(
                    from_email=sender_email,
                    to_emails=[email],
                    subject='OTP from FutureWork Land - Classroom',
                    html_content=render_template('admin_forgot_password.html',
                                                 oneTimePassword=oneTimePassword))
                sg = SendGridAPIClient(os.environ.get('SENDGRID_API_KEY'))
                sg.send(message)
                return make_response({"status": True,
                                      "message": f"Success, Email has been sent to {email}"}, 200)
            else:
                return make_response({"status": False,
                                      "message": "Failed. This account is not verified. Please check your email."}, 200)

        except:
            return make_response({"status": False,
                                  "message": "Failed. UnAuthorised Email"}, 200)

    except:
        return make_response({"status": False,
                              "message": "Something went wrong"}, 500)


@app_api.route('/change-forgot-password', methods=["POST"])
@cross_origin()
def forgot_password_validate():
    try:
        email = request.json.get('email')
        user_otp = request.json.get('otp')
        if not email:
            return make_response({"status": False,
                                  "message": "Missing email"}, 400)
        if not user_otp:
            return make_response({"status": False,
                                  "message": "Missing OTP"}, 400)
        userEnterOtp = user_otp.encode("utf-8")
        db = connect()
        cursorObject = db.cursor()
        cursorObject.execute(query.userEmailExist.format(email=email))
        fetch = cursorObject.fetchone()
        # print(fetch)
        passwordByUser = fetch["temp_code"].strip("b")
        passwordByUser = passwordByUser.replace("'", "")
        passwordByUser = passwordByUser.encode("utf-8")
        # print(passwordByUser)
        if bcrypt.checkpw(userEnterOtp, passwordByUser) and email == fetch["email"]:
            # isVerified = 1
            # cursorObject.execute(query.verifyAdmin.format(adminUserEmail=adminUserEmail, isVerified=isVerified))
            # db.commit()
            newPassword = request.json.get('newPassword')
            if len(newPassword) < 8:
                return make_response({"status": False,
                                      "message": "Error, Length must must be more than 8 characters"}, 400)
            hashed = bcrypt.hashpw(newPassword.encode('utf-8'), bcrypt.gensalt())
            cursorObject.execute(query.updateUserPassword.format(
                email=email, password=hashed
            ))
            db.commit()
            return make_response({"status": True,
                                  "statusCode": 200,
                                  "message": "Success, Password Changed."}, 200)
        else:
            return make_response({"status": False,
                                  "message": "Error, OTP doesn't match"}, 200)

    except Exception as e:
        print(e)
        return make_response({"status": False,
                              "message": "Something went wrong"}, 500)


@app_api.route('/view-access_level', methods=['GET'])
@cross_origin()
def get_access_level():
    try:
        db = connect()
        cursorObject = db.cursor()
        cursorObject.execute(query.get_access_level.format())
        data = cursorObject.fetchall()
        return make_response({"status": True,
                              "code": 200,
                              'message': "Success",
                              "data": data}, 200)
    except Exception as e:
        return make_response({"status": False,
                              "message": "Something went wrong"}, 500)


@app_api.route('/view-roles', methods=['GET'])
@cross_origin()
def get_roles():
    try:
        db = connect()
        cursorObject = db.cursor()
        cursorObject.execute(query.admin_view_roles.format())
        data = cursorObject.fetchall()
        return make_response({"status": True,
                              "code": 200,
                              'message': "Success",
                              "data": data}, 200)
    except Exception as e:
        return make_response({"status": False,
                              "message": "Something went wrong"}, 500)


@app_api.route('/get-technology-id', methods=['GET'])
@cross_origin()
@jwt_required()
def get_technology():
    try:
        db = connect()
        cursorObject = db.cursor()
        admin_email = get_jwt_identity()
        cursorObject.execute(query.get_technology_details.format())
        data = cursorObject.fetchall()
        return make_response({"status": True,
                              "code": 200,
                              'message': "Technology Added",
                              "data": data}, 200)
    except Exception as e:
        print(e)
        return make_response({"status": False,
                              "message": "Something went wrong"}, 500)


@app_api.route('/user/view-projects', methods=['GET'])
@cross_origin()
@jwt_required()
def user_view_projects():
    try:
        db = connect()
        cursorObject = db.cursor()
        email = get_jwt_identity()
        cursorObject.execute(query.userEmailExist.format(email=email))
        get_data = cursorObject.fetchone()
        company_name = get_data['company_name']
        user_id = get_data['user_id']
        cursorObject.execute(query.user_get_project_details.format(user_id=user_id))
        project_data = cursorObject.fetchall()
        return make_response({"status": True,
                              "code": 200,
                              'message': "Success",
                              "data": project_data}, 200)
    except Exception as e:
        print(e)
        return make_response({"status": False,
                              "message": "Something went wrong"}, 500)


@app_api.route('/user/view-projects-by-id', methods=['POST'])
@cross_origin()
@jwt_required()
def user_view_projects_by_id():
    try:
        db = connect()
        cursorObject = db.cursor()
        email = get_jwt_identity()
        project_id = request.json.get('project_id')
        cursorObject.execute(query.userEmailExist.format(email=email))
        get_data = cursorObject.fetchone()
        company_name = get_data['company_name']
        user_id = get_data['user_id']
        cursorObject.execute(query.get_project_users.format(project_id=project_id))
        project_users = cursorObject.fetchall()
        cursorObject.execute(query.get_project_technology.format(project_id=project_id))
        project_technology = cursorObject.fetchall()
        cursorObject.execute(query.get_project_details_by_id.format(project_id=project_id))
        project_data = cursorObject.fetchall()
        data = {"project_data": project_data, "project_users": project_users,
                "project_technology": project_technology}
        return make_response({"status": True,
                              "code": 200,
                              'message': "Success",
                              "data": data}, 200)
    except Exception as e:
        print(e)
        return make_response({"status": False,
                              "message": "Something went wrong"}, 500)


@app_api.route('/user/view-project-roles', methods=['POST'])
@cross_origin()
@jwt_required()
def view_project_users_roles():
    try:
        db = connect()
        cursorObject = db.cursor()
        email = get_jwt_identity()
        project_id = request.json.get('project_id')
        user_id = request.json.get('user_id')
        cursorObject.execute(query.viewProjectUserRoles.format(user_id=user_id,
                                                               project_id=project_id))
        data = cursorObject.fetchall()
        return make_response({"status": True,
                              "code": 200,
                              'message': "Success",
                              "data": data}, 200)
    except Exception as e:
        print(e)
        return make_response({"status": False,
                              "message": "Something went wrong"}, 500)


@app_api.route('/user/create-epic', methods=['POST'])
@cross_origin()
@jwt_required()
def user_create_epic():
    try:
        db = connect()
        cursorObject = db.cursor()
        email = get_jwt_identity()
        unique_id = uuid.uuid4()
        epic_id = str(unique_id)
        project_id = request.json.get('project_id')
        epic_subject = request.json.get('epic_subject')
        epic_description = request.json.get('epic_description')
        if not (project_id and epic_subject and epic_description):
            return make_response({"status": False,
                                  "message": "Missing Params"},
                                 200)
        cursorObject.execute(query.userEmailExist.format(email=email))
        get_data = cursorObject.fetchone()
        user_id = get_data['user_id']
        cursorObject.execute(query.getUserProjectRoles.format(user_id=user_id, project_id=project_id))
        get_data = cursorObject.fetchall()
        role_id_list = []
        for __role_id__ in get_data:
            role_id = int(__role_id__['role_id'])
            if role_id == 2:
                role_id_list.append(role_id)
            else:
                pass
        if len(role_id_list) == 0:
            return make_response({"status": False,
                                  "message": "Sorry you don't have permission to do this operation."},
                                 200)
        if role_id_list[0] == 2:
            cursorObject.execute(query.insertEpic.format(epic_id=epic_id,
                                                         project_id=project_id,
                                                         user_id=user_id,
                                                         epic_subject=epic_subject,
                                                         epic_description=epic_description))
            db.commit()
            return make_response({"status": True,
                                  "code": 200,
                                  'message': "Success"}, 200)
        else:
            return make_response({"status": False,
                                  "message": "Sorry you don't have permission to do this operation."},
                                 200)

    except Exception as e:
        print(e)
        return make_response({"status": False,
                              "message": "Something went wrong"}, 500)


@app_api.route('/user/update-epic', methods=['POST'])
@cross_origin()
@jwt_required()
def user_update_epic():
    try:
        db = connect()
        cursorObject = db.cursor()
        email = get_jwt_identity()
        project_id = request.json.get('project_id')
        epic_id = request.json.get("epic_id")
        if not (project_id and epic_id):
            return make_response({"status": False,
                                  "message": "Missing Params"},
                                 200)
        cursorObject.execute(query.userEmailExist.format(email=email))
        get_data = cursorObject.fetchone()
        user_id = get_data['user_id']
        cursorObject.execute(query.getUserProjectRoles.format(user_id=user_id, project_id=project_id))
        get_data = cursorObject.fetchall()
        role_id_list = []
        for __role_id__ in get_data:
            role_id = int(__role_id__['role_id'])
            if role_id == 2:
                role_id_list.append(role_id)
            else:
                pass
        if len(role_id_list) == 0:
            return make_response({"status": False,
                                  "message": "Sorry you don't have permission to do this operation."},
                                 200)
        if role_id_list[0] == 2:
            cursorObject.execute(query.checkEpic.format(project_id=project_id, epic_id=epic_id))
            epic_data = cursorObject.fetchone()
            epic_subject = request.json.get('epic_subject') or epic_data['epic_subject']
            epic_description = request.json.get('epic_description') or epic_data['epic_description']
            cursorObject.execute(query.updateEpic.format(epic_id=epic_id,
                                                         epic_subject=epic_subject,
                                                         epic_description=epic_description))
            db.commit()
            return make_response({"status": True,
                                  "code": 200,
                                  'message': "Updated"}, 200)
        else:
            return make_response({"status": False,
                                  "message": "Sorry you don't have permission to do this operation."},
                                 200)

    except Exception as e:
        print(e)
        return make_response({"status": False,
                              "message": "Something went wrong"}, 500)


@app_api.route('/user/view-epic', methods=['POST'])
@cross_origin()
@jwt_required()
def user_view_epic():
    try:
        db = connect()
        cursorObject = db.cursor()
        email = get_jwt_identity()
        project_id = request.json.get('project_id')
        if not project_id:
            return make_response({"status": False,
                                  "message": "Missing Params"},
                                 200)
        cursorObject.execute(query.userEmailExist.format(email=email))
        get_data = cursorObject.fetchone()
        user_id = get_data['user_id']
        cursorObject.execute(query.getUserProjectRoles.format(user_id=user_id, project_id=project_id))
        get_data = cursorObject.fetchall()
        role_id_list = []
        for __role_id__ in get_data:
            role_id = int(__role_id__['role_id'])
            if role_id == 7:
                role_id_list.append(role_id)
            else:
                pass
        if len(role_id_list) == 0:
            return make_response({"status": False,
                                  "message": "Sorry you don't have permission to do this operation."},
                                 200)
        if role_id_list[0] == 7:
            cursorObject.execute(query.viewEpic.format(project_id=project_id))
            data = cursorObject.fetchall()
            return make_response({"status": True,
                                  "code": 200,
                                  'message': "Success",
                                  "data": data}, 200)
        else:
            return make_response({"status": False,
                                  "message": "Sorry you don't have permission to do this operation."},
                                 200)

    except Exception as e:
        print(e)
        return make_response({"status": False,
                              "message": "Something went wrong"}, 500)


@app_api.route('/user/create-story', methods=['POST'])
@cross_origin()
@jwt_required()
def user_create_story():
    try:
        db = connect()
        cursorObject = db.cursor()
        email = get_jwt_identity()
        unique_id = uuid.uuid4()
        story_id = str(unique_id)
        project_id = request.json.get('project_id')
        epic_id = request.json.get('epic_id')
        story_subject = request.json.get('story_subject')
        story_description = request.json.get('story_description')
        if not (project_id and epic_id and story_subject and story_description):
            return make_response({"status": False,
                                  "message": "Missing Params"},
                                 200)
        cursorObject.execute(query.userEmailExist.format(email=email))
        get_data = cursorObject.fetchone()
        user_id = get_data['user_id']
        cursorObject.execute(query.getUserProjectRoles.format(user_id=user_id, project_id=project_id))
        get_data = cursorObject.fetchall()
        role_id_list = []
        for __role_id__ in get_data:
            role_id = int(__role_id__['role_id'])
            if role_id == 3:
                role_id_list.append(role_id)
            else:
                pass
        if len(role_id_list) == 0:
            return make_response({"status": False,
                                  "message": "Sorry you don't have permission to do this operation."},
                                 200)
        if role_id_list[0] == 3:
            cursorObject.execute(query.insertStory.format(story_id=story_id,
                                                          epic_id=epic_id,
                                                          project_id=project_id,
                                                          user_id=user_id,
                                                          story_subject=story_subject,
                                                          story_description=story_description))
            db.commit()
            return make_response({"status": True,
                                  "code": 200,
                                  'message': "Success"}, 200)
        else:
            return make_response({"status": False,
                                  "message": "Sorry you don't have permission to do this operation."},
                                 200)

    except Exception as e:
        print(e)
        return make_response({"status": False,
                              "message": "Something went wrong"}, 500)


@app_api.route('/user/update-story', methods=['POST'])
@cross_origin()
@jwt_required()
def user_update_story():
    try:
        db = connect()
        cursorObject = db.cursor()
        email = get_jwt_identity()
        project_id = request.json.get('project_id')
        story_id = request.json.get("story_id")
        if not (project_id and story_id):
            return make_response({"status": False,
                                  "message": "Missing Params"},
                                 200)
        cursorObject.execute(query.userEmailExist.format(email=email))
        get_data = cursorObject.fetchone()
        user_id = get_data['user_id']
        cursorObject.execute(query.getUserProjectRoles.format(user_id=user_id, project_id=project_id))
        get_data = cursorObject.fetchall()
        role_id_list = []
        for __role_id__ in get_data:
            role_id = int(__role_id__['role_id'])
            if role_id == 3:
                role_id_list.append(role_id)
            else:
                pass
        if len(role_id_list) == 0:
            return make_response({"status": False,
                                  "message": "Sorry you don't have permission to do this operation."},
                                 200)
        if role_id_list[0] == 3:
            cursorObject.execute(query.checkStory.format(project_id=project_id, story_id=story_id))
            epic_data = cursorObject.fetchone()
            story_subject = request.json.get('story_subject') or epic_data['story_subject']
            story_description = request.json.get('story_description') or epic_data['story_description']
            cursorObject.execute(query.updateStory.format(story_id=story_id,
                                                          story_subject=story_subject,
                                                          story_description=story_description))
            db.commit()
            return make_response({"status": True,
                                  "code": 200,
                                  'message': "Updated"}, 200)
        else:
            return make_response({"status": False,
                                  "message": "Sorry you don't have permission to do this operation."},
                                 200)

    except Exception as e:
        print(e)
        return make_response({"status": False,
                              "message": "Something went wrong"}, 500)


@app_api.route('/user/view-story', methods=['POST'])
@cross_origin()
@jwt_required()
def user_view_story():
    try:
        db = connect()
        cursorObject = db.cursor()
        email = get_jwt_identity()
        project_id = request.json.get('project_id')
        epic_id = request.json.get('epic_id')
        if not project_id and epic_id:
            return make_response({"status": False,
                                  "message": "Missing Params"},
                                 200)
        cursorObject.execute(query.userEmailExist.format(email=email))
        get_data = cursorObject.fetchone()
        user_id = get_data['user_id']
        cursorObject.execute(query.getUserProjectRoles.format(user_id=user_id, project_id=project_id))
        get_data = cursorObject.fetchall()
        role_id_list = []
        for __role_id__ in get_data:
            role_id = int(__role_id__['role_id'])
            if role_id == 6:
                role_id_list.append(role_id)
            else:
                pass
        if len(role_id_list) == 0:
            return make_response({"status": False,
                                  "message": "Sorry you don't have permission to do this operation."},
                                 200)
        if role_id_list[0] == 6:
            cursorObject.execute(query.viewStory.format(project_id=project_id, epic_id=epic_id))
            data = cursorObject.fetchall()
            return make_response({"status": True,
                                  "code": 200,
                                  'message': "Success",
                                  "data": data}, 200)
        else:
            return make_response({"status": False,
                                  "message": "Sorry you don't have permission to do this operation."},
                                 200)

    except Exception as e:
        print(e)
        return make_response({"status": False,
                              "message": "Something went wrong"}, 500)


@app_api.route('/user/create-task', methods=['POST'])
@cross_origin()
@jwt_required()
def user_create_task():
    try:
        db = connect()
        cursorObject = db.cursor()
        email = get_jwt_identity()
        unique_id = uuid.uuid4()
        tasks_id = str(unique_id)
        project_id = request.json.get('project_id')
        story_id = request.json.get('story_id')
        task_subject = request.json.get('task_subject')
        task_description = request.json.get('task_description')
        priority = request.json.get('priority')
        estimated_time = request.json.get('estimated_time')
        status = 1
        if not (project_id and story_id and task_subject and task_description and priority):
            return make_response({"status": False,
                                  "message": "Missing Params"},
                                 200)
        cursorObject.execute(query.userEmailExist.format(email=email))
        get_data = cursorObject.fetchone()
        user_id = get_data['user_id']
        cursorObject.execute(query.getUserProjectRoles.format(user_id=user_id, project_id=project_id))
        get_data = cursorObject.fetchall()
        role_id_list = []
        for __role_id__ in get_data:
            role_id = int(__role_id__['role_id'])
            if role_id == 4:
                role_id_list.append(role_id)
            else:
                pass
        if len(role_id_list) == 0:
            return make_response({"status": False,
                                  "message": "Sorry you don't have permission to do this operation."},
                                 200)
        if role_id_list[0] == 4:
            cursorObject.execute(query.insertTask.format(story_id=story_id,
                                                         tasks_id=tasks_id,
                                                         project_id=project_id,
                                                         user_id=user_id,
                                                         task_subject=task_subject,
                                                         task_description=task_description,
                                                         priority=priority,
                                                         status=status,
                                                         user_assigned=user_id,
                                                         estimated_time=estimated_time
                                                         ))
            cursorObject.execute(query.insertTaskAssignee.format(
                tasks_id=tasks_id,
                project_id=project_id,
                user_id=user_id
            ))
            cursorObject.execute(query.insertTaskStatusLog.format(
                tasks_id=tasks_id,
                project_id=project_id,
                user_id=user_id,
                tasks_status=status
            ))
            db.commit()
            return make_response({"status": True,
                                  "code": 200,
                                  'message': "Success"}, 200)
        else:
            return make_response({"status": False,
                                  "message": "Sorry you don't have permission to do this operation."},
                                 200)

    except Exception as e:
        print(e)
        return make_response({"status": False,
                              "message": "Something went wrong"}, 500)


@app_api.route('/user/update-task', methods=['POST'])
@cross_origin()
@jwt_required()
def user_update_task():
    try:
        db = connect()
        cursorObject = db.cursor()
        email = get_jwt_identity()
        project_id = request.json.get("project_id")
        tasks_id = request.json.get("tasks_id")
        if not (project_id and tasks_id):
            return make_response({"status": False, "message": "Missing Params"}, 200)
        cursorObject.execute(query.checkEmail.format(email=email))
        get_data = cursorObject.fetchone()
        admin_id = get_data["admin_id"]
        cursorObject.execute(
            query.checkTask.format(project_id=project_id, tasks_id=tasks_id)
        )
        epic_data = cursorObject.fetchone()
        task_subject = request.json.get("task_subject") or epic_data["task_subject"]
        task_description = (
            request.json.get("task_description") or epic_data["task_description"]
        )
        priority = request.json.get("priority") or epic_data["priority"]
        user_assigned = request.json.get("user_assigned")
        status = request.json.get("status")
        estimated_time = (
            request.json.get("estimated_time") or epic_data["estimated_time"]
        )
        if status is not None:
            cursorObject.execute(
                query.insertTaskStatusLog.format(
                    tasks_id=tasks_id,
                    project_id=project_id,
                    admin_id=admin_id,
                    tasks_status=status,
                )
            )
        if user_assigned is not None:
            cursorObject.execute(
                query.insertTaskAssigneeUser.format(
                    tasks_id=tasks_id, project_id=project_id, user_id=user_assigned
                )
            )
        cursorObject.execute(
            query.updateTask.format(
                tasks_id=tasks_id,
                task_subject=task_subject,
                task_description=task_description,
                priority=priority,
                status=status,
                user_assigned=user_assigned,
                estimated_time=estimated_time,
            )
        )
        db.commit()
        return make_response({"status": True, "code": 200, "message": "Updated"}, 200)
    except Exception as e:
        print(e)
        return make_response({"status": False, "message": "Something went wrong"}, 500)


@app_api.route('/user/view-task', methods=['POST'])
@cross_origin()
@jwt_required()
def user_view_task():
    try:
        db = connect()
        cursorObject = db.cursor()
        email = get_jwt_identity()
        project_id = request.json.get('project_id')
        story_id = request.json.get('story_id')
        if not project_id and story_id:
            return make_response({"status": False,
                                  "message": "Missing Params"},
                                 200)
        cursorObject.execute(query.userEmailExist.format(email=email))
        get_data = cursorObject.fetchone()
        user_id = get_data['user_id']
        cursorObject.execute(query.getUserProjectRoles.format(user_id=user_id, project_id=project_id))
        get_data = cursorObject.fetchall()
        role_id_list = []
        for __role_id__ in get_data:
            role_id = int(__role_id__['role_id'])
            if role_id == 5:
                role_id_list.append(role_id)
            else:
                pass
        if len(role_id_list) == 0:
            return make_response({"status": False,
                                  "message": "Sorry you don't have permission to do this operation."},
                                 200)
        if role_id_list[0] == 5:
            cursorObject.execute(query.viewTasks.format(project_id=project_id, story_id=story_id))
            data = cursorObject.fetchall()
            return make_response({"status": True,
                                  "code": 200,
                                  'message': "Success",
                                  "data": data}, 200)
        else:
            return make_response({"status": False,
                                  "message": "Sorry you don't have permission to do this operation."},
                                 200)

    except Exception as e:
        print(e)
        return make_response({"status": False,
                              "message": "Something went wrong"}, 500)


@app_api.route('/user/view-task-by-id', methods=['POST'])
@cross_origin()
@jwt_required()
def user_view_task_by_id():
    try:
        db = connect()
        cursorObject = db.cursor()
        email = get_jwt_identity()
        tasks_id = request.json.get('tasks_id')
        project_id = request.json.get("project_id")
        if not tasks_id:
            return make_response({"status": False,
                                  "message": "Missing Params"},
                                 200)
        cursorObject.execute(query.userEmailExist.format(email=email))
        get_data = cursorObject.fetchone()
        user_id = get_data['user_id']
        cursorObject.execute(query.getUserProjectRoles.format(user_id=user_id, project_id=project_id))
        get_data = cursorObject.fetchall()
        role_id_list = []
        for __role_id__ in get_data:
            role_id = int(__role_id__['role_id'])
            if role_id == 5:
                role_id_list.append(role_id)
            else:
                pass
        if len(role_id_list) == 0:
            return make_response({"status": False,
                                  "message": "Sorry you don't have permission to do this operation."},
                                 200)
        if role_id_list[0] == 5:
            cursorObject.execute(query.viewTaskById.format(tasks_id=tasks_id))
            data = cursorObject.fetchall()
            return make_response({"status": True,
                                  "code": 200,
                                  'message': "Success",
                                  "data": data}, 200)
        else:
            return make_response({"status": False,
                                  "message": "Sorry you don't have permission to do this operation."},
                                 200)

    except Exception as e:
        print(e)
        return make_response({"status": False,
                              "message": "Something went wrong"}, 500)


@app_api.route('/user/code-gen', methods=['POST'])
@cross_origin()
@jwt_required()
def user_code_generation():
    try:
        db = connect()
        cursorObject = db.cursor()
        email = get_jwt_identity()
        tasks_id = request.json.get('tasks_id')
        project_id = request.json.get("project_id")
        code_query = request.json.get('code_query')
        unique_id = uuid.uuid4()
        code_id = str(unique_id)
        cursorObject.execute(query.userEmailExist.format(email=email))
        get_data = cursorObject.fetchone()
        user_id = get_data['user_id']
        cursorObject.execute(query.getUserProjectRoles.format(user_id=user_id, project_id=project_id))
        get_data = cursorObject.fetchall()
        role_id_list = []
        for __role_id__ in get_data:
            role_id = int(__role_id__['role_id'])
            if role_id == 1:
                role_id_list.append(role_id)
            else:
                pass
        if len(role_id_list) == 0:
            return make_response({"status": False,
                                  "message": "Sorry you don't have permission to do this operation."},
                                 200)
        if role_id_list[0] == 1:
            codeCheck = cursorObject.execute(query.viewCodeGen.format(tasks_id=tasks_id))
            # print(emailCheck)
            if codeCheck >= 1:
                db.rollback()
                return make_response({"status": False,
                                      "message": "Code has already been generated."}, 200)
            response = openai.Completion.create(
                # model="code-davinci-002",
                model="text-davinci-003",
                prompt=code_query,
                temperature=0.5,
                max_tokens=3800,
                top_p=1,
                frequency_penalty=0,
                presence_penalty=0
            )
            code_response = response.choices[0].text
            encoded_response = base64.b64encode(code_response.encode('utf-8')).decode('utf-8')
            cursorObject.execute(query.insertCodeData.format(
                user_id=user_id,
                project_id=project_id,
                code_id=code_id,
                tasks_id=tasks_id,
                code_query=code_query,
                code_response=encoded_response
            ))
            db.commit()
            return make_response({"status": True,
                                  "code": 200,
                                  'message': "Success",
                                  "data": code_response}, 200)

        else:
            return make_response({"status": False,
                                  "message": "Sorry you don't have permission to do this operation."},
                                 200)
    except Exception as e:
        print(e)
        return make_response({"status": False,
                              "msg": f"Something went wrong, {e}"})


@app_api.route('/user/view-code-gen', methods=['POST'])
@cross_origin()
@jwt_required()
def user_view_code_generation():
    try:
        db = connect()
        cursorObject = db.cursor()
        email = get_jwt_identity()
        tasks_id = request.json.get('tasks_id')
        cursorObject.execute(query.viewCodeGen.format(tasks_id=tasks_id))
        get_data = cursorObject.fetchone()
        if get_data is None:
            return make_response({"status": True,
                                  "code": 200,
                                  'message': "Success",
                                  "data": []}, 200)
        generated_code = get_data['code_response']
        code_id = get_data['code_id']
        decoded_response = base64.b64decode(generated_code.encode('utf-8')).decode('utf-8')
        data = {"generated_code": decoded_response, "code_id": code_id}
        return make_response({"status": True,
                              "code": 200,
                              'message': "Success",
                              "data": data}, 200)
    except Exception as e:
        print(e)
        return make_response({"status": False,
                              "msg": f"Something went wrong, {e}"})


@app_api.route('/user/code-re-gen', methods=['POST'])
@cross_origin()
@jwt_required()
def user_code_regeneration():
    try:
        db = connect()
        cursorObject = db.cursor()
        email = get_jwt_identity()
        project_id = request.json.get('project_id')
        code_id = request.json.get('code_id')
        code_query = request.json.get('code_query')
        cursorObject.execute(query.userEmailExist.format(email=email))
        get_data = cursorObject.fetchone()
        user_id = get_data['user_id']
        cursorObject.execute(query.getUserProjectRoles.format(user_id=user_id, project_id=project_id))
        get_data = cursorObject.fetchall()
        role_id_list = []
        for __role_id__ in get_data:
            role_id = int(__role_id__['role_id'])
            if role_id == 1:
                role_id_list.append(role_id)
            else:
                pass
        if len(role_id_list) == 0:
            return make_response({"status": False,
                                  "message": "Sorry you don't have permission to do this operation."},
                                 200)
        if role_id_list[0] == 1:
            response = openai.Completion.create(
                # model="code-davinci-002",
                model="text-davinci-003",
                prompt=code_query,
                temperature=0.5,
                max_tokens=3800,
                top_p=1,
                frequency_penalty=0,
                presence_penalty=0
            )
            code_response = response.choices[0].text
            encoded_response = base64.b64encode(code_response.encode('utf-8')).decode('utf-8')
            cursorObject.execute(query.updateCodeGen.format(
                code_id=code_id,
                code_query=code_query,
                code_response=encoded_response
            ))
            db.commit()
            return make_response({"status": True,
                                  "code": 200,
                                  'message': "Updated",
                                  "data": code_response}, 200)

        else:
            return make_response({"status": False,
                                  "message": "Sorry you don't have permission to do this operation."},
                                 200)
    except Exception as e:
        print(e)
        return make_response({"status": False,
                              "msg": f"Something went wrong, {e}"})


@app_api.route('/user/add-project', methods=['POST'])
@cross_origin()
@jwt_required()
def add_projects():
    try:
        db = connect()
        cursorObject = db.cursor()
        email = get_jwt_identity()
        unique_id = uuid.uuid4()
        project_id = str(unique_id)
        project_name = request.json.get('project_name')
        project_description = request.json.get('project_description')
        project_url = request.json.get('project_url')
        cursorObject.execute(query.userEmailExist.format(email=email))
        get_data = cursorObject.fetchone()
        user_id = get_data['user_id']
        cursorObject.execute(query.getUserAccessLevel.format(user_id=user_id))
        get_data = cursorObject.fetchone()
        userAccessLevel = get_data['access_level']
        userAccessLevel = int(userAccessLevel)
        if userAccessLevel == 5:
            cursorObject.execute(query.create_project.format(
                project_id=project_id,
                project_name=project_name,
                project_description=project_description,
                project_url=project_url,
                user_id=user_id
            ))
            cursorObject.execute(query.insertProjectMember.format(
                project_id=project_id,
                user_added=user_id,
                user_id=user_id
            ))
            db.commit()
            data = {"project_id": project_id, "project_name": project_name}
            return make_response({"status": True,
                                  "code": 200,
                                  'message': "Project Created",
                                  "data": data}, 200)
        elif userAccessLevel == 6:
            cursorObject.execute(query.create_project.format(
                project_id=project_id,
                project_name=project_name,
                project_description=project_description,
                project_url=project_url,
                user_id=user_id
            ))
            db.commit()
            data = {"project_id": project_id, "project_name": project_name}
            return make_response({"status": True,
                                  "code": 200,
                                  'message': "Project Created",
                                  "data": data}, 200)
        else:
            return make_response({"status": False,
                                  "message": "Sorry you don't have permission to do this operation."},
                                 200)
    except Exception as e:
        print(e)
        return make_response({"status": False,
                              "message": "Something went wrong"}, 500)


@app_api.route('/user/edit-project', methods=['POST'])
@cross_origin()
@jwt_required()
def edit_projects():
    try:
        db = connect()
        cursorObject = db.cursor()
        email = get_jwt_identity()
        project_id = request.json.get('project_id')
        cursorObject.execute(query.checkProjectDetails.format(project_id=project_id))
        get_project_data = cursorObject.fetchone()
        project_name = request.json.get('project_name') or get_project_data['project_name']
        project_description = request.json.get('project_description') or get_project_data['project_description']
        project_url = request.json.get('project_url') or get_project_data['project_url']
        cursorObject.execute(query.userEmailExist.format(email=email))
        get_data = cursorObject.fetchone()
        user_id = get_data['user_id']
        cursorObject.execute(query.getUserAccessLevel.format(user_id=user_id))
        get_data = cursorObject.fetchone()
        userAccessLevel = get_data['access_level']
        userAccessLevel = int(userAccessLevel)
        if userAccessLevel == 5:
            cursorObject.execute(query.update_project_details.format(
                project_id=project_id,
                project_name=project_name,
                project_description=project_description,
                project_url=project_url,
                user_id=user_id
            ))
            db.commit()
            data = {"project_id": project_id, "project_name": project_name}
            return make_response({"status": True,
                                  "code": 200,
                                  'message': "Project Updated",
                                  "data": data}, 200)
        if userAccessLevel == 6:
            cursorObject.execute(query.update_project_details.format(
                project_id=project_id,
                project_name=project_name,
                project_description=project_description,
                project_url=project_url,
                user_id=user_id
            ))
            db.commit()
            data = {"project_id": project_id, "project_name": project_name}
            return make_response({"status": True,
                                  "code": 200,
                                  'message': "Project Updated",
                                  "data": data}, 200)
        else:
            return make_response({"status": False,
                                  "message": "Sorry you don't have permission to do this operation."},
                                 200)
    except Exception as e:
        print(e)
        return make_response({"status": False,
                              "message": "Something went wrong"}, 500)


@app_api.route('/user/add-project-members', methods=['POST'])
@cross_origin()
@jwt_required()
def add_projects_members():
    try:
        db = connect()
        cursorObject = db.cursor()
        email = get_jwt_identity()
        project_id = request.json.get('project_id')
        user_id = request.json.get('user_id')
        cursorObject.execute(query.userEmailExist.format(email=email))
        get_data = cursorObject.fetchone()
        user_added = get_data['user_id']
        cursorObject.execute(query.getUserAccessLevel.format(user_id=user_added))
        get_data = cursorObject.fetchone()
        userAccessLevel = get_data['access_level']
        userAccessLevel = int(userAccessLevel)
        if userAccessLevel == 2:
            for __user_id__ in user_id:
                cursorObject.execute(query.create_project_users.format(
                    project_id=project_id,
                    user_id=__user_id__,
                    user_added=user_added
                ))
                db.commit()
            return make_response({"status": True,
                                  "code": 200,
                                  'message': "Users Added"}, 200)
        elif userAccessLevel == 5:
            for __user_id__ in user_id:
                cursorObject.execute(query.create_project_users.format(
                    project_id=project_id,
                    user_id=__user_id__,
                    user_added=user_added
                ))
                db.commit()
            return make_response({"status": True,
                                  "code": 200,
                                  'message': "Users Added"}, 200)
        elif userAccessLevel == 6:
            for __user_id__ in user_id:
                cursorObject.execute(query.create_project_users.format(
                    project_id=project_id,
                    user_id=__user_id__,
                    user_added=user_added
                ))
                db.commit()
            return make_response({"status": True,
                                  "code": 200,
                                  'message': "Users Added"}, 200)
        else:
            return make_response({"status": False,
                                  "message": "Sorry you don't have permission to do this operation."},
                                 200)
    except Exception as e:
        print(e)
        return make_response({"status": False,
                              "message": "Something went wrong"}, 500)


@app_api.route('/user/remove-project-members', methods=['POST'])
@cross_origin()
@jwt_required()
def remove_projects_members():
    try:
        db = connect()
        cursorObject = db.cursor()
        email = get_jwt_identity()
        project_id = request.json.get('project_id')
        user_id = request.json.get('user_id')
        cursorObject.execute(query.userEmailExist.format(email=email))
        get_data = cursorObject.fetchone()
        user_added = get_data['user_id']
        cursorObject.execute(query.getUserAccessLevel.format(user_id=user_added))
        get_data = cursorObject.fetchone()
        userAccessLevel = get_data['access_level']
        userAccessLevel = int(userAccessLevel)
        if userAccessLevel == 2:
            cursorObject.execute(query.remove_project_member.format(
                project_id=project_id,
                user_id=user_id
            ))
            db.commit()
            return make_response({"status": True,
                                  "code": 200,
                                  'message': "Users Removed"}, 200)
        elif userAccessLevel == 5:
            cursorObject.execute(query.remove_project_member.format(
                project_id=project_id,
                user_id=user_id
            ))
            db.commit()
            return make_response({"status": True,
                                  "code": 200,
                                  'message': "Users Removed"}, 200)
        elif userAccessLevel == 6:
            cursorObject.execute(query.remove_project_member.format(
                project_id=project_id,
                user_id=user_id
            ))
            db.commit()
            return make_response({"status": True,
                                  "code": 200,
                                  'message': "Users Removed"}, 200)
        else:
            return make_response({"status": False,
                                  "message": "Sorry you don't have permission to do this operation."},
                                 200)
    except Exception as e:
        print(e)
        return make_response({"status": False,
                              "message": "Something went wrong"}, 500)


@app_api.route('/user/add-project-technology', methods=['POST'])
@cross_origin()
@jwt_required()
def add_projects_technology():
    try:
        db = connect()
        cursorObject = db.cursor()
        email = get_jwt_identity()
        project_id = request.json.get('project_id')
        technology_id = request.json.get('technology_id')
        cursorObject.execute(query.userEmailExist.format(email=email))
        get_data = cursorObject.fetchone()
        user_added = get_data['user_id']
        cursorObject.execute(query.getUserAccessLevel.format(user_id=user_added))
        get_data = cursorObject.fetchone()
        userAccessLevel = get_data['access_level']
        userAccessLevel = int(userAccessLevel)
        if userAccessLevel == 2:
            for __technology_id__ in technology_id:
                cursorObject.execute(query.create_project_technology.format(
                    project_id=project_id,
                    technology_id=__technology_id__,
                    user_added=user_added
                ))
                db.commit()
            return make_response({"status": True,
                                  "code": 200,
                                  'message': "Technology Added"}, 200)
        if userAccessLevel == 5:
            for __technology_id__ in technology_id:
                cursorObject.execute(query.create_project_technology.format(
                    project_id=project_id,
                    technology_id=__technology_id__,
                    user_added=user_added
                ))
                db.commit()
            return make_response({"status": True,
                                  "code": 200,
                                  'message': "Technology Added"}, 200)
        if userAccessLevel == 6:
            for __technology_id__ in technology_id:
                cursorObject.execute(query.create_project_technology.format(
                    project_id=project_id,
                    technology_id=__technology_id__,
                    user_added=user_added
                ))
                db.commit()
            return make_response({"status": True,
                                  "code": 200,
                                  'message': "Technology Added"}, 200)
        else:
            return make_response({"status": False,
                                  "message": "Sorry you don't have permission to do this operation."},
                                 200)
    except Exception as e:
        print(e)
        return make_response({"status": False,
                              "message": "Something went wrong"}, 500)


@app_api.route('/user/remove-project-technology', methods=['POST'])
@cross_origin()
@jwt_required()
def remove_projects_technology():
    try:
        db = connect()
        cursorObject = db.cursor()
        email = get_jwt_identity()
        project_id = request.json.get('project_id')
        technology_id = request.json.get('technology_id')
        cursorObject.execute(query.userEmailExist.format(email=email))
        get_data = cursorObject.fetchone()
        user_added = get_data['user_id']
        cursorObject.execute(query.getUserAccessLevel.format(user_id=user_added))
        get_data = cursorObject.fetchone()
        userAccessLevel = get_data['access_level']
        userAccessLevel = int(userAccessLevel)
        if userAccessLevel == 2:
            cursorObject.execute(query.remove_project_technology.format(
                project_id=project_id,
                technology_id=technology_id
            ))
            db.commit()
            return make_response({"status": True,
                                  "code": 200,
                                  'message': "Technology Removed"}, 200)
        elif userAccessLevel == 5:
            cursorObject.execute(query.remove_project_technology.format(
                project_id=project_id,
                technology_id=technology_id
            ))
            db.commit()
            return make_response({"status": True,
                                  "code": 200,
                                  'message': "Technology Removed"}, 200)
        elif userAccessLevel == 6:
            cursorObject.execute(query.remove_project_technology.format(
                project_id=project_id,
                technology_id=technology_id
            ))
            db.commit()
            return make_response({"status": True,
                                  "code": 200,
                                  'message': "Technology Removed"}, 200)
        else:
            return make_response({"status": False,
                                  "message": "Sorry you don't have permission to do this operation."},
                                 200)
    except Exception as e:
        print(e)
        return make_response({"status": False,
                              "message": "Something went wrong"}, 500)


@app_api.route('/user/remove-project-story', methods=['POST'])
@cross_origin()
@jwt_required()
def user_remove_project_story():
    try:
        db = connect()
        cursorObject = db.cursor()
        email = get_jwt_identity()
        project_id = request.json.get('project_id')
        story_id = request.json.get('story_id')
        if not (project_id and story_id):
            return make_response({"status": False,
                                  "message": "Missing Params"},
                                 200)
        cursorObject.execute(query.userEmailExist.format(email=email))
        get_data = cursorObject.fetchone()
        user_added = get_data['user_id']
        cursorObject.execute(query.getUserAccessLevel.format(user_id=user_added))
        get_data = cursorObject.fetchone()
        userAccessLevel = get_data['access_level']
        userAccessLevel = int(userAccessLevel)
        if userAccessLevel == 2:
            cursorObject.execute(query.deleteStoryByID.format(project_id=project_id, story_id=story_id))
            cursorObject.execute(query.deleteStoryByTasksID.format(project_id=project_id, story_id=story_id))
            db.commit()
            return make_response({"status": True,
                                  "code": 200,
                                  'message': "Deleted"}, 200)
        elif userAccessLevel == 5:
            cursorObject.execute(query.deleteStoryByID.format(project_id=project_id, story_id=story_id))
            cursorObject.execute(query.deleteStoryByTasksID.format(project_id=project_id, story_id=story_id))
            db.commit()
            return make_response({"status": True,
                                  "code": 200,
                                  'message': "Deleted"}, 200)
        elif userAccessLevel == 6:
            cursorObject.execute(query.deleteStoryByID.format(project_id=project_id, story_id=story_id))
            cursorObject.execute(query.deleteStoryByTasksID.format(project_id=project_id, story_id=story_id))
            db.commit()
            return make_response({"status": True,
                                  "code": 200,
                                  'message': "Deleted"}, 200)
        else:
            return make_response({"status": False,
                                  "message": "Sorry you don't have permission to do this operation."},
                                 200)
    except Exception as e:
        print(e)
        return make_response({"status": False,
                              "msg": f"Something went wrong, {e}"})


@app_api.route('/user/remove-project-epic', methods=['POST'])
@cross_origin()
@jwt_required()
def user_remove_project_epic():
    try:
        db = connect()
        cursorObject = db.cursor()
        email = get_jwt_identity()
        project_id = request.json.get('project_id')
        epic_id = request.json.get('epic_id')
        if not (project_id and epic_id):
            return make_response({"status": False,
                                  "message": "Missing Params"},
                                 200)
        cursorObject.execute(query.userEmailExist.format(email=email))
        get_data = cursorObject.fetchone()
        user_added = get_data['user_id']
        cursorObject.execute(query.getUserAccessLevel.format(user_id=user_added))
        get_data = cursorObject.fetchone()
        userAccessLevel = get_data['access_level']
        userAccessLevel = int(userAccessLevel)
        if userAccessLevel == 2:
            cursorObject.execute(query.deleteEpicByID.format(project_id=project_id, epic_id=epic_id))
            cursorObject.execute(query.deleteStoryByEpicID.format(project_id=project_id, epic_id=epic_id))
            db.commit()
            return make_response({"status": True,
                                  "code": 200,
                                  'message': "Deleted"}, 200)
        elif userAccessLevel == 5:
            cursorObject.execute(query.deleteEpicByID.format(project_id=project_id, epic_id=epic_id))
            cursorObject.execute(query.deleteStoryByEpicID.format(project_id=project_id, epic_id=epic_id))
            db.commit()
            return make_response({"status": True,
                                  "code": 200,
                                  'message': "Deleted"}, 200)
        elif userAccessLevel == 6:
            cursorObject.execute(query.deleteEpicByID.format(project_id=project_id, epic_id=epic_id))
            cursorObject.execute(query.deleteStoryByEpicID.format(project_id=project_id, epic_id=epic_id))
            db.commit()
            return make_response({"status": True,
                                  "code": 200,
                                  'message': "Deleted"}, 200)
        else:
            return make_response({"status": False,
                                  "message": "Sorry you don't have permission to do this operation."},
                                 200)
    except Exception as e:
        print(e)
        return make_response({"status": False,
                              "msg": f"Something went wrong, {e}"})


@app_api.route('/user/remove-project-tasks', methods=['POST'])
@cross_origin()
@jwt_required()
def user_remove_project_tasks():
    try:
        db = connect()
        cursorObject = db.cursor()
        email = get_jwt_identity()
        project_id = request.json.get('project_id')
        tasks_id = request.json.get('tasks_id')
        if not (project_id and tasks_id):
            return make_response({"status": False,
                                  "message": "Missing Params"},
                                 200)
        cursorObject.execute(query.userEmailExist.format(email=email))
        get_data = cursorObject.fetchone()
        user_added = get_data['user_id']
        cursorObject.execute(query.getUserAccessLevel.format(user_id=user_added))
        get_data = cursorObject.fetchone()
        userAccessLevel = get_data['access_level']
        userAccessLevel = int(userAccessLevel)
        if userAccessLevel == 2:
            cursorObject.execute(query.deleteTasksByID.format(project_id=project_id, tasks_id=tasks_id))
            db.commit()
            return make_response({"status": True,
                                  "code": 200,
                                  'message': "Deleted"}, 200)
        # elif userAccessLevel == 5:
        #     cursorObject.execute(query.deleteTasksByID.format(project_id=project_id, tasks_id=tasks_id))
        #     db.commit()
        #     return make_response({"status": True,
        #                           "code": 200,
        #                           'message': "Deleted"}, 200)
        # elif userAccessLevel == 6:
        #     cursorObject.execute(query.deleteTasksByID.format(project_id=project_id, tasks_id=tasks_id))
        #     db.commit()
        #     return make_response({"status": True,
        #                           "code": 200,
        #                           'message': "Deleted"}, 200)
        else:
            return make_response({"status": False,
                                  "message": "Sorry you don't have permission to do this operation."},
                                 200)
    except Exception as e:
        print(e)
        return make_response({"status": False,
                              "msg": f"Something went wrong, {e}"})


@app_api.route('/user/change-tasks-assigned', methods=['POST'])
@cross_origin()
@jwt_required()
def user_change_tasks_assigned():
    try:
        db = connect()
        cursorObject = db.cursor()
        email = get_jwt_identity()
        project_id = request.json.get('project_id')
        tasks_id = request.json.get('tasks_id')
        user_assigned = request.json.get('user_assigned')
        if not (project_id and tasks_id):
            return make_response({"status": False,
                                  "message": "Missing Params"},
                                 200)
        cursorObject.execute(query.userEmailExist.format(email=email))
        get_data = cursorObject.fetchone()
        user_id = get_data['user_id']
        cursorObject.execute(query.checkUserProjectMemberStatus.format(user_id=user_assigned, project_id=project_id))
        userStatus = cursorObject.fetchone()
        if userStatus is None:
            return make_response({"status": False,
                                  "message": "Sorry you don't have permission to do this operation."},
                                 200)
        else:
            cursorObject.execute(query.updateTaskAssignee.format(tasks_id=tasks_id, user_assigned=user_assigned))
            cursorObject.execute(query.insertTaskAssignee.format(
                tasks_id=tasks_id,
                project_id=project_id,
                user_id=user_assigned
            ))
            db.commit()
            return make_response({"status": True,
                                  "code": 200,
                                  'message': "success"}, 200)
    except Exception as e:
        print(e)
        return make_response({"status": False,
                              "msg": f"Something went wrong, {e}"})


@app_api.route('/user/change-tasks-status', methods=['POST'])
@cross_origin()
@jwt_required()
def user_change_tasks_status():
    try:
        db = connect()
        cursorObject = db.cursor()
        email = get_jwt_identity()
        project_id = request.json.get('project_id')
        tasks_id = request.json.get('tasks_id')
        status = request.json.get('status')
        if not (project_id and tasks_id):
            return make_response({"status": False,
                                  "message": "Missing Params"},
                                 200)
        cursorObject.execute(query.userEmailExist.format(email=email))
        get_data = cursorObject.fetchone()
        user_id = get_data['user_id']
        cursorObject.execute(query.checkUserProjectMemberStatus.format(user_id=user_id,
                                                                       project_id=project_id))
        userStatus = cursorObject.fetchone()
        if userStatus is None:
            return make_response({"status": False,
                                  "message": "Sorry you don't have permission to do this operation."},
                                 200)
        else:
            cursorObject.execute(query.updateTaskStatus.format(tasks_id=tasks_id, status=status))
            cursorObject.execute(query.insertTaskStatusLog.format(
                tasks_id=tasks_id,
                project_id=project_id,
                user_id=user_id,
                tasks_status=status
            ))
            db.commit()
            return make_response({"status": True,
                                  "code": 200,
                                  'message': "success"}, 200)
    except Exception as e:
        print(e)
        return make_response({"status": False,
                              "msg": f"Something went wrong, {e}"})


@app_api.route('/user/add-project-documents', methods=['POST'])
@cross_origin()
@jwt_required()
def user_add_project_documents():
    try:
        db = connect()
        cursorObject = db.cursor()
        email = get_jwt_identity()
        project_id = request.form['project_id']
        project_attachment = request.files['project_attachment']
        if not (project_id and project_attachment):
            return make_response({"status": False,
                                  "message": "Missing Params"},
                                 200)
        cursorObject.execute(query.userEmailExist.format(email=email))
        get_data = cursorObject.fetchone()
        user_id = get_data['user_id']
        company_name = get_data['company_name']
        file_name = project_attachment.filename
        unique_id = uuid.uuid4()
        file_unique_name = str(unique_id)
        stored_file_name = file_unique_name + file_name
        bucket_name = DevConfig.bucket_name
        folder_name = f'{company_name}'
        cursorObject.execute(query.getUserAccessLevel.format(user_id=user_id))
        get_data = cursorObject.fetchone()
        userAccessLevel = get_data['access_level']
        userAccessLevel = int(userAccessLevel)
        if userAccessLevel == 2:
            s3.put_object(Body=project_attachment, Bucket=bucket_name,
                          Key=folder_name + '/' + project_id + '/' + "project_files" + '/' + stored_file_name)
            # Company name is set default to Utah Tech Labs
            file_url = "https://lowcodedev.s3.amazonaws.com/Utah+Tech+Labs/" \
                       f"{project_id}/project_files/{stored_file_name}"

            cursorObject.execute(query.insertProjectAttachment.format(
                project_id=project_id,
                user_id=user_id,
                company_name=company_name,
                file_name=file_name,
                file_url=file_url,
                stored_file_name=stored_file_name
            ))
            db.commit()
            data = {"project_id": project_id, "file_url": file_url}
            return make_response({"status": True,
                                  "code": 200,
                                  'message': "uploaded",
                                  "data": data}, 200)
        elif userAccessLevel == 5:
            s3.put_object(Body=project_attachment, Bucket=bucket_name,
                          Key=folder_name + '/' + project_id + '/' + "project_files" + '/' + stored_file_name)
            # Company name is set default to Utah Tech Labs
            file_url = "https://lowcodedev.s3.amazonaws.com/Utah+Tech+Labs/" \
                       f"{project_id}/project_files/{stored_file_name}"
            cursorObject.execute(query.insertProjectAttachment.format(
                project_id=project_id,
                user_id=user_id,
                company_name=company_name,
                file_name=file_name,
                file_url=file_url,
                stored_file_name=stored_file_name
            ))
            db.commit()
            data = {"project_id": project_id, "file_url": file_url}
            return make_response({"status": True,
                                  "code": 200,
                                  'message': "uploaded",
                                  "data": data}, 200)
        elif userAccessLevel == 6:
            s3.put_object(Body=project_attachment, Bucket=bucket_name,
                          Key=folder_name + '/' + project_id + '/' + "project_files" + '/' + stored_file_name)
            file_url = "https://lowcodedev.s3.amazonaws.com/Utah+Tech+Labs/" \
                       f"{project_id}/project_files/{stored_file_name}"
            cursorObject.execute(query.insertProjectAttachment.format(
                project_id=project_id,
                user_id=user_id,
                company_name=company_name,
                file_name=file_name,
                file_url=file_url,
                stored_file_name=stored_file_name
            ))
            db.commit()
            data = {"project_id": project_id, "file_url": file_url}
            return make_response({"status": True,
                                  "code": 200,
                                  'message': "uploaded",
                                  "data": data}, 200)
        else:
            return make_response({"status": False,
                                  "message": "Sorry you don't have permission to do this operation."},
                                 200)
    except Exception as e:
        print(e)
        return make_response({"status": False,
                              "msg": f"Something went wrong, {e}"})


@app_api.route('/user/delete-project-documents', methods=['DELETE'])
@cross_origin()
@jwt_required()
def user_delete_project_documents():
    try:
        db = connect()
        cursorObject = db.cursor()
        email = get_jwt_identity()
        project_id = request.json['project_id']
        stored_file_name = request.json.get('stored_file_name')
        if not (project_id and stored_file_name):
            return make_response({"status": False,
                                  "message": "Missing params"}, 400)
        cursorObject.execute(query.userEmailExist.format(email=email))
        get_data = cursorObject.fetchone()
        user_id = get_data['user_id']
        company_name = get_data['company_name']
        bucket_name = DevConfig.bucket_name
        folder_name = f'{company_name}'
        cursorObject.execute(query.getUserAccessLevel.format(user_id=user_id))
        get_data = cursorObject.fetchone()
        userAccessLevel = get_data['access_level']
        userAccessLevel = int(userAccessLevel)
        if userAccessLevel == 2:
            s3.delete_object(Bucket=bucket_name,
                             Key=folder_name + '/' + project_id + '/' + "project_files" + '/' + stored_file_name)
            cursorObject.execute(query.deleteProjectAttachment.format(
                stored_file_name=stored_file_name
            ))
            db.commit()
            return make_response({"status": True,
                                  "code": 200,
                                  'message': "deleted"}, 200)
        elif userAccessLevel == 5:
            s3.delete_object(Bucket=bucket_name,
                             Key=folder_name + '/' + project_id + '/' + "project_files" + '/' + stored_file_name)
            cursorObject.execute(query.deleteProjectAttachment.format(
                stored_file_name=stored_file_name
            ))
            db.commit()
            return make_response({"status": True,
                                  "code": 200,
                                  'message': "deleted"}, 200)
        elif userAccessLevel == 6:
            s3.delete_object(Bucket=bucket_name,
                             Key=folder_name + '/' + project_id + '/' + "project_files" + '/' + stored_file_name)
            cursorObject.execute(query.deleteProjectAttachment.format(
                stored_file_name=stored_file_name
            ))
            db.commit()
            return make_response({"status": True,
                                  "code": 200,
                                  'message': "deleted"}, 200)
        else:
            return make_response({"status": False,
                                  "message": "Sorry you don't have permission to do this operation."},
                                 200)
    except Exception as e:
        print(e)
        return make_response({"status": False,
                              "msg": f"Something went wrong, {e}"})


@app_api.route('/user/view-project-documents', methods=['POST'])
@cross_origin()
@jwt_required()
def user_view_project_documents():
    try:
        db = connect()
        cursorObject = db.cursor()
        email = get_jwt_identity()
        project_id = request.json['project_id']
        if not project_id:
            return make_response({"status": False,
                                  "message": "Missing params"}, 400)
        cursorObject.execute(query.userEmailExist.format(email=email))
        get_data = cursorObject.fetchone()
        user_id = get_data['user_id']
        cursorObject.execute(query.getUserProjectRoles.format(user_id=user_id, project_id=project_id))
        get_data = cursorObject.fetchall()
        role_id_list = []
        for __role_id__ in get_data:
            role_id = int(__role_id__['role_id'])
            if role_id == 7:
                role_id_list.append(role_id)
            else:
                pass
        if len(role_id_list) == 0:
            return make_response({"status": False,
                                  "message": "Sorry you don't have permission to do this operation."},
                                 200)
        if role_id_list[0] == 7:
            cursorObject.execute(query.getProjectAttachment.format(
                project_id=project_id
            ))
            data = cursorObject.fetchall()
            return make_response({"status": True,
                                  "code": 200,
                                  'message': "success",
                                  "data": data}, 200)

        else:
            return make_response({"status": False,
                                  "message": "Sorry you don't have permission to do this operation."},
                                 200)
    except Exception as e:
        print(e)
        return make_response({"status": False,
                              "msg": f"Something went wrong, {e}"})


@app_api.route('/user/add-task-documents', methods=['POST'])
@cross_origin()
@jwt_required()
def user_add_task_documents():
    try:
        db = connect()
        cursorObject = db.cursor()
        email = get_jwt_identity()
        project_id = request.form['project_id']
        tasks_id = request.form['tasks_id']
        tasks_attachment = request.files['tasks_attachment']
        if not (project_id and tasks_attachment and tasks_id):
            return make_response({"status": False,
                                  "message": "Missing params"}, 400)
        cursorObject.execute(query.userEmailExist.format(email=email))
        get_data = cursorObject.fetchone()
        user_id = get_data['user_id']
        company_name = get_data['company_name']
        file_name = tasks_attachment.filename
        unique_id = uuid.uuid4()
        file_unique_name = str(unique_id)
        stored_file_name = file_unique_name + file_name
        bucket_name = DevConfig.bucket_name
        folder_name = f'{company_name}'
        cursorObject.execute(query.getUserProjectRoles.format(user_id=user_id, project_id=project_id))
        get_data = cursorObject.fetchall()
        role_id_list = []
        for __role_id__ in get_data:
            role_id = int(__role_id__['role_id'])
            if role_id == 5:
                role_id_list.append(role_id)
            else:
                pass
        if len(role_id_list) == 0:
            return make_response({"status": False,
                                  "message": "Sorry you don't have permission to do this operation."},
                                 200)
        if role_id_list[0] == 5:
            s3.put_object(Body=tasks_attachment, Bucket=bucket_name,
                          Key=folder_name + '/' + project_id + '/' + "tasks_files" + '/' + stored_file_name)
            # Company name is set default to Utah Tech Labs
            file_url = "https://lowcodedev.s3.amazonaws.com/Utah+Tech+Labs/" \
                       f"{project_id}/tasks_files/{stored_file_name}"
            cursorObject.execute(query.insertTaskAttachment.format(
                project_id=project_id,
                user_id=user_id,
                tasks_id=tasks_id,
                file_name=file_name,
                file_url=file_url,
                stored_file_name=stored_file_name
            ))
            db.commit()
            data = {"project_id": project_id, "file_url": file_url}
            return make_response({"status": True,
                                  "code": 200,
                                  'message': "uploaded",
                                  "data": data}, 200)

        else:
            return make_response({"status": False,
                                  "message": "Sorry you don't have permission to do this operation."},
                                 200)
    except Exception as e:
        print(e)
        return make_response({"status": False,
                              "msg": f"Something went wrong, {e}"})


@app_api.route('/user/delete-task-documents', methods=['DELETE'])
@cross_origin()
@jwt_required()
def user_delete_task_documents():
    try:
        db = connect()
        cursorObject = db.cursor()
        email = get_jwt_identity()
        project_id = request.json['project_id']
        stored_file_name = request.json.get('stored_file_name')
        if not (project_id and stored_file_name):
            return make_response({"status": False,
                                  "message": "Missing params"}, 400)
        cursorObject.execute(query.userEmailExist.format(email=email))
        get_data = cursorObject.fetchone()
        user_id = get_data['user_id']
        company_name = get_data['company_name']
        bucket_name = DevConfig.bucket_name
        folder_name = f'{company_name}'
        cursorObject.execute(query.getUserProjectRoles.format(user_id=user_id, project_id=project_id))
        get_data = cursorObject.fetchall()
        role_id_list = []
        for __role_id__ in get_data:
            role_id = int(__role_id__['role_id'])
            if role_id == 5:
                role_id_list.append(role_id)
            else:
                pass
        if len(role_id_list) == 0:
            return make_response({"status": False,
                                  "message": "Sorry you don't have permission to do this operation."},
                                 200)
        if role_id_list[0] == 5:
            s3.delete_object(Bucket=bucket_name,
                             Key=folder_name + '/' + project_id + '/' + "tasks_files" + '/' + stored_file_name)
            cursorObject.execute(query.deleteTaskAttachment.format(
                stored_file_name=stored_file_name
            ))
            db.commit()
            return make_response({"status": True,
                                  "code": 200,
                                  'message': "deleted"}, 200)

        else:
            return make_response({"status": False,
                                  "message": "Sorry you don't have permission to do this operation."},
                                 200)
    except Exception as e:
        print(e)
        return make_response({"status": False,
                              "msg": f"Something went wrong, {e}"})


@app_api.route('/user/view-task-documents', methods=['POST'])
@cross_origin()
@jwt_required()
def user_view_task_documents():
    try:
        db = connect()
        cursorObject = db.cursor()
        email = get_jwt_identity()
        project_id = request.json['project_id']
        tasks_id = request.json['tasks_id']
        if not tasks_id:
            return make_response({"status": False,
                                  "message": "Missing params"}, 400)
        cursorObject.execute(query.userEmailExist.format(email=email))
        get_data = cursorObject.fetchone()
        user_id = get_data['user_id']
        company_name = get_data['company_name']
        bucket_name = DevConfig.bucket_name
        folder_name = f'{company_name}'
        cursorObject.execute(query.getUserProjectRoles.format(user_id=user_id, project_id=project_id))
        get_data = cursorObject.fetchall()
        role_id_list = []
        for __role_id__ in get_data:
            role_id = int(__role_id__['role_id'])
            if role_id == 5:
                role_id_list.append(role_id)
            else:
                pass
        if len(role_id_list) == 0:
            return make_response({"status": False,
                                  "message": "Sorry you don't have permission to do this operation."},
                                 200)
        if role_id_list[0] == 5:
            cursorObject.execute(query.getTaskAttachment.format(
                tasks_id=tasks_id
            ))
            data = cursorObject.fetchall()
            return make_response({"status": True,
                                  "code": 200,
                                  'message': "success",
                                  "data": data}, 200)

        else:
            return make_response({"status": False,
                                  "message": "Sorry you don't have permission to do this operation."},
                                 200)
    except Exception as e:
        print(e)
        return make_response({"status": False,
                              "msg": f"Something went wrong, {e}"})


@app_api.route('/user/add-task-work-log', methods=['POST'])
@cross_origin()
@jwt_required()
def user_add_task_work_log():
    try:
        db = connect()
        cursorObject = db.cursor()
        email = get_jwt_identity()
        project_id = request.json.get('project_id')
        tasks_id = request.json.get('tasks_id')
        time_spent = request.json.get('time_spent')
        log_description = request.json.get("log_description")
        if not (project_id and tasks_id and time_spent and log_description):
            return make_response({"status": False,
                                  "message": "Missing params"}, 400)
        if time_spent:
            hh, mm = time_spent.split('.')
            hh = int(hh)
            mm = int(mm)
            if hh >= 12:
                return make_response({"status": False,
                                      "message": "Invalid hours logged. Max 12 hours can be logged"},
                                     200)
            if mm >= 60:
                return make_response({"status": False,
                                      "message": "Invalid hours logged. Max 59 minutes can be logged"},
                                     200)
        cursorObject.execute(query.userEmailExist.format(email=email))
        get_data = cursorObject.fetchone()
        user_id = get_data['user_id']
        company_name = get_data['company_name']
        cursorObject.execute(query.getUserProjectRoles.format(user_id=user_id, project_id=project_id))
        get_data = cursorObject.fetchall()
        role_id_list = []
        for __role_id__ in get_data:
            role_id = int(__role_id__['role_id'])
            if role_id == 5:
                role_id_list.append(role_id)
            else:
                pass
        if len(role_id_list) == 0:
            return make_response({"status": False,
                                  "message": "Sorry you don't have permission to do this operation."},
                                 200)
        if role_id_list[0] == 5:
            cursorObject.execute(query.insertWorkLog.format(
                tasks_id=tasks_id,
                user_id=user_id,
                project_id=project_id,
                time_spent=time_spent,
                log_description=log_description
            ))
            db.commit()
            return make_response({"status": True,
                                  "code": 200,
                                  'message': "success"}, 200)

        else:
            return make_response({"status": False,
                                  "message": "Sorry you don't have permission to do this operation."},
                                 200)
    except Exception as e:
        print(e)
        return make_response({"status": False,
                              "msg": f"Something went wrong, {e}"})


@app_api.route('/user/edit-task-work-log', methods=['POST'])
@cross_origin()
@jwt_required()
def user_edit_task_work_log():
    try:
        db = connect()
        cursorObject = db.cursor()
        email = get_jwt_identity()
        work_log_id = request.json.get("work_log_id")
        project_id = request.json.get("project_id")
        if not work_log_id:
            return make_response({"status": False,
                                  "message": "Missing params"}, 400)
        cursorObject.execute(query.userEmailExist.format(email=email))
        get_data = cursorObject.fetchone()
        user_id = get_data['user_id']
        company_name = get_data['company_name']
        cursorObject.execute(query.getUserProjectRoles.format(user_id=user_id, project_id=project_id))
        get_data = cursorObject.fetchall()
        role_id_list = []
        for __role_id__ in get_data:
            role_id = int(__role_id__['role_id'])
            if role_id == 5:
                role_id_list.append(role_id)
            else:
                pass
        if len(role_id_list) == 0:
            return make_response({"status": False,
                                  "message": "Sorry you don't have permission to do this operation."},
                                 200)
        if role_id_list[0] == 5:
            cursorObject.execute(query.checkWorkLog.format(work_log_id=work_log_id))
            get_work_log = cursorObject.fetchone()
            time_spent = request.json.get('time_spent') or get_work_log['time_spent']
            log_description = request.json.get('log_description') or get_work_log['log_description']
            cursorObject.execute(query.updateWorkLog.format(
                work_log_id=work_log_id,
                time_spent=time_spent,
                log_description=log_description
            ))
            db.commit()
            return make_response({"status": True,
                                  "code": 200,
                                  'message': "updated"}, 200)

        else:
            return make_response({"status": False,
                                  "message": "Sorry you don't have permission to do this operation."},
                                 200)
    except Exception as e:
        print(e)
        return make_response({"status": False,
                              "msg": f"Something went wrong, {e}"})


@app_api.route('/user/total-task-work-log', methods=['POST'])
@cross_origin()
@jwt_required()
def user_total_task_work_log():
    try:
        db = connect()
        cursorObject = db.cursor()
        email = get_jwt_identity()
        project_id = request.json.get("project_id")
        tasks_id = request.json.get('tasks_id')
        if not (project_id and tasks_id):
            return make_response({"status": False,
                                  "message": "Missing params"}, 400)
        cursorObject.execute(query.userEmailExist.format(email=email))
        get_data = cursorObject.fetchone()
        user_id = get_data['user_id']
        company_name = get_data['company_name']
        cursorObject.execute(query.getUserProjectRoles.format(user_id=user_id, project_id=project_id))
        get_data = cursorObject.fetchall()
        role_id_list = []
        for __role_id__ in get_data:
            role_id = int(__role_id__['role_id'])
            if role_id == 5:
                role_id_list.append(role_id)
            else:
                pass
        if len(role_id_list) == 0:
            return make_response({"status": False,
                                  "message": "Sorry you don't have permission to do this operation."},
                                 200)
        if role_id_list[0] == 5:
            data = {}
            cursorObject.execute(query.checkTasksWorkLog.format(tasks_id=tasks_id))
            get_work_log = cursorObject.fetchall()
            total_time_spent = timedelta()

            for time_spent in get_work_log:
                time_string = time_spent['time_spent']
                hours, minutes = map(int, time_string.split('.'))
                time_delta = timedelta(hours=hours, minutes=minutes)
                total_time_spent += time_delta
                str_total_time = str(total_time_spent)
                time_parts = str_total_time.split(":")
                hour_minute_string = time_parts[0] + "." + time_parts[1]
                data_dict = {"total_hours": hour_minute_string}
                data.update(data_dict)
            if len(data) <= 0:
                return make_response({"status": True,
                                      "code": 200,
                                      'message': "success",
                                      "data": {"total_hours": ""}}, 200)
            return make_response({"status": True,
                                  "code": 200,
                                  'message': "success",
                                  "data": data}, 200)

        else:
            return make_response({"status": False,
                                  "message": "Sorry you don't have permission to do this operation."},
                                 200)
    except Exception as e:
        print(e)
        return make_response({"status": False,
                              "msg": f"Something went wrong, {e}"})


@app_api.route('/user/task-work-log-by-user', methods=['POST'])
@cross_origin()
@jwt_required()
def user_task_work_log_user():
    try:
        db = connect()
        cursorObject = db.cursor()
        email = get_jwt_identity()
        project_id = request.json.get("project_id")
        tasks_id = request.json.get('tasks_id')
        if not (project_id and tasks_id):
            return make_response({"status": False,
                                  "message": "Missing params"}, 400)
        cursorObject.execute(query.userEmailExist.format(email=email))
        get_data = cursorObject.fetchone()
        user_id = get_data['user_id']
        company_name = get_data['company_name']
        cursorObject.execute(query.getUserProjectRoles.format(user_id=user_id, project_id=project_id))
        get_data = cursorObject.fetchall()
        role_id_list = []
        for __role_id__ in get_data:
            role_id = int(__role_id__['role_id'])
            if role_id == 5:
                role_id_list.append(role_id)
            else:
                pass
        if len(role_id_list) == 0:
            return make_response({"status": False,
                                  "message": "Sorry you don't have permission to do this operation."},
                                 200)
        if role_id_list[0] == 5:
            cursorObject.execute(query.checkTaskByUser.format(tasks_id=tasks_id))
            get_work_log = cursorObject.fetchall()
            return make_response({"status": True,
                                  "code": 200,
                                  'message': "success",
                                  "data": get_work_log}, 200)

        else:
            return make_response({"status": False,
                                  "message": "Sorry you don't have permission to do this operation."},
                                 200)
    except Exception as e:
        print(e)
        return make_response({"status": False,
                              "msg": f"Something went wrong, {e}"})


@app_api.route('/user/total-task-work-log-by-user', methods=['POST'])
@cross_origin()
@jwt_required()
def user_total_task_work_log_user():
    try:
        db = connect()
        cursorObject = db.cursor()
        email = get_jwt_identity()
        project_id = request.json.get("project_id")
        tasks_id = request.json.get('tasks_id')
        user_id = request.json.get('user_id')
        if not (project_id and tasks_id):
            return make_response({"status": False,
                                  "message": "Missing params"}, 400)
        cursorObject.execute(query.userEmailExist.format(email=email))
        get_data = cursorObject.fetchone()
        __user_id__ = get_data['user_id']
        # company_name = get_data['company_name']
        cursorObject.execute(query.getUserProjectRoles.format(user_id=__user_id__, project_id=project_id))
        get_data = cursorObject.fetchall()
        role_id_list = []
        for __role_id__ in get_data:
            role_id = int(__role_id__['role_id'])
            if role_id == 5:
                role_id_list.append(role_id)
            else:
                pass
        if len(role_id_list) == 0:
            return make_response({"status": False,
                                  "message": "Sorry you don't have permission to do this operation."},
                                 200)
        if role_id_list[0] == 5:
            data = []
            for users in user_id:
                cursorObject.execute(query.checkTaskByUserID.format(tasks_id=tasks_id, user_id=users))
                get_work_log = cursorObject.fetchall()
                time_spent_by_email = defaultdict(timedelta)
                for item in get_work_log:
                    time_parts = item['time_spent']
                    email = item['email']
                    hours, minutes = map(int, time_parts.split('.'))
                    time_delta = timedelta(hours=hours, minutes=minutes)
                    time_spent_by_email[email] += time_delta
                for email, time_spent in time_spent_by_email.items():
                    hours, remainder = divmod(time_spent.seconds, 3600)
                    minutes, seconds = divmod(remainder, 60)
                    total_time_spent = float(f"{hours}.{minutes}")
                    # print(f"{email}: {hours} hours, {minutes} minutes")
                    dict_data = {"email": email, "total_time_spent": total_time_spent}
                    data.append(dict_data)
            return make_response({"status": True,
                                  "code": 200,
                                  'message': "success",
                                  "data": data}, 200)

        else:
            return make_response({"status": False,
                                  "message": "Sorry you don't have permission to do this operation."},
                                 200)
    except Exception as e:
        print(e)
        return make_response({"status": False,
                              "msg": f"Something went wrong, {e}"})


@app_api.route('/user/add-comment', methods=['POST'])
@cross_origin()
@jwt_required()
def user_add_comment():
    try:
        db = connect()
        cursorObject = db.cursor()
        email = get_jwt_identity()
        project_id = request.json.get("project_id")
        tasks_id = request.json.get('tasks_id')
        if not (project_id and tasks_id):
            return make_response({"status": False,
                                  "message": "Missing params"}, 400)
        cursorObject.execute(query.userEmailExist.format(email=email))
        get_data = cursorObject.fetchone()
        __user_id__ = get_data['user_id']
        # company_name = get_data['company_name']
        cursorObject.execute(query.getUserAccessLevel.format(user_id=__user_id__))
        get_data = cursorObject.fetchone()
        userAccessLevel = get_data['access_level']
        userAccessLevel = int(userAccessLevel)
        if userAccessLevel == 2:
            manager_comment = request.json.get("manager_comment")
            if not manager_comment or manager_comment is None:
                return make_response({"status": False,
                                      "message": "Sorry you don't have permission to do this operation."},
                                     200)
            cursorObject.execute(query.insertManagerComment.format(
                user_id=__user_id__, project_id=project_id, tasks_id=tasks_id, manager_comment=manager_comment))
            db.commit()
            return make_response({"status": True,
                                  "code": 200,
                                  'message': "success"}, 200)
        else:
            user_comment = request.json.get("user_comment")
            if not user_comment or user_comment is None:
                return make_response({"status": False,
                                      "message": "Sorry you don't have permission to do this operation."},
                                     200)
            cursorObject.execute(query.getUserProjectRoles.format(user_id=__user_id__, project_id=project_id))
            get_data = cursorObject.fetchall()
            role_id_list = []
            for __role_id__ in get_data:
                role_id = int(__role_id__['role_id'])
                if role_id == 5:
                    role_id_list.append(role_id)
                else:
                    pass
            if len(role_id_list) == 0:
                return make_response({"status": False,
                                      "message": "Sorry you don't have permission to do this operation."},
                                     200)
            if role_id_list[0] == 5:
                cursorObject.execute(query.insertUserComment.format(
                    user_id=__user_id__, project_id=project_id, tasks_id=tasks_id, user_comment=user_comment))
                db.commit()
                return make_response({"status": True,
                                      "code": 200,
                                      'message': "success"}, 200)
            else:
                return make_response({"status": False,
                                      "message": "Sorry you don't have permission to do this operation."},
                                     200)
    except Exception as e:
        print(e)
        return make_response({"status": False,
                              "msg": f"Something went wrong, {e}"})


@app_api.route('/user/edit-comment', methods=['POST'])
@cross_origin()
@jwt_required()
def user_edit_comment():
    try:
        db = connect()
        cursorObject = db.cursor()
        email = get_jwt_identity()
        project_id = request.json.get("project_id")
        comment_id = request.json.get('comment_id')
        if not (project_id and comment_id):
            return make_response({"status": False,
                                  "message": "Missing params"}, 400)
        cursorObject.execute(query.userEmailExist.format(email=email))
        get_data = cursorObject.fetchone()
        __user_id__ = get_data['user_id']
        # company_name = get_data['company_name']
        cursorObject.execute(query.getUserAccessLevel.format(user_id=__user_id__))
        get_data = cursorObject.fetchone()
        userAccessLevel = get_data['access_level']
        userAccessLevel = int(userAccessLevel)
        if userAccessLevel == 2:
            manager_comment = request.json.get("manager_comment")
            if not manager_comment or manager_comment is None:
                return make_response({"status": False,
                                      "message": "Sorry you don't have permission to do this operation."},
                                     200)
            cursorObject.execute(query.updateManagerComment.format(
                comment_id=comment_id, manager_comment=manager_comment))
            db.commit()
            return make_response({"status": True,
                                  "code": 200,
                                  'message': "updated"}, 200)
        else:
            user_comment = request.json.get("user_comment")
            if not user_comment or user_comment is None:
                return make_response({"status": False,
                                      "message": "Sorry you don't have permission to do this operation."},
                                     200)
            cursorObject.execute(query.getUserProjectRoles.format(user_id=__user_id__, project_id=project_id))
            get_data = cursorObject.fetchall()
            role_id_list = []
            for __role_id__ in get_data:
                role_id = int(__role_id__['role_id'])
                if role_id == 5:
                    role_id_list.append(role_id)
                else:
                    pass
            if len(role_id_list) == 0:
                return make_response({"status": False,
                                      "message": "Sorry you don't have permission to do this operation."},
                                     200)
            if role_id_list[0] == 5:
                cursorObject.execute(query.updateUserComment.format(
                    comment_id=comment_id, user_comment=user_comment))
                db.commit()
                return make_response({"status": True,
                                      "code": 200,
                                      'message': "updated"}, 200)
            else:
                return make_response({"status": False,
                                      "message": "Sorry you don't have permission to do this operation."},
                                     200)
    except Exception as e:
        print(e)
        return make_response({"status": False,
                              "msg": f"Something went wrong, {e}"})


@app_api.route('/user/delete-comment', methods=['DELETE'])
@cross_origin()
@jwt_required()
def user_delete_comment():
    try:
        db = connect()
        cursorObject = db.cursor()
        email = get_jwt_identity()
        project_id = request.json.get("project_id")
        comment_id = request.json.get('comment_id')
        if not (project_id and comment_id):
            return make_response({"status": False,
                                  "message": "Missing params"}, 400)
        cursorObject.execute(query.userEmailExist.format(email=email))
        get_data = cursorObject.fetchone()
        __user_id__ = get_data['user_id']
        # company_name = get_data['company_name']
        cursorObject.execute(query.getUserAccessLevel.format(user_id=__user_id__))
        get_data = cursorObject.fetchone()
        userAccessLevel = get_data['access_level']
        userAccessLevel = int(userAccessLevel)
        if userAccessLevel == 2:
            cursorObject.execute(query.deleteComment.format(
                comment_id=comment_id))
            db.commit()
            return make_response({"status": True,
                                  "code": 200,
                                  'message': "deleted"}, 200)
        else:
            cursorObject.execute(query.getUserProjectRoles.format(user_id=__user_id__, project_id=project_id))
            get_data = cursorObject.fetchall()
            role_id_list = []
            for __role_id__ in get_data:
                role_id = int(__role_id__['role_id'])
                if role_id == 5:
                    role_id_list.append(role_id)
                else:
                    pass
            if len(role_id_list) == 0:
                return make_response({"status": False,
                                      "message": "Sorry you don't have permission to do this operation."},
                                     200)
            if role_id_list[0] == 5:
                cursorObject.execute(query.checkUserComment.format(
                    comment_id=comment_id))
                comment_data = cursorObject.fetchone()
                comment_user_id = comment_data['user_id']
                if comment_user_id == __user_id__:
                    cursorObject.execute(query.deleteComment.format(
                        comment_id=comment_id))
                    db.commit()
                    return make_response({"status": True,
                                          "code": 200,
                                          'message': "deleted"}, 200)
                else:
                    return make_response({"status": False,
                                          "message": "Sorry you don't have permission to do this operation."},
                                         200)
            else:
                return make_response({"status": False,
                                      "message": "Sorry you don't have permission to do this operation."},
                                     200)
    except Exception as e:
        print(e)
        return make_response({"status": False,
                              "msg": f"Something went wrong, {e}"})


@app_api.route('/user/view-comment', methods=['POST'])
@cross_origin()
@jwt_required()
def user_view_comment():
    try:
        db = connect()
        cursorObject = db.cursor()
        email = get_jwt_identity()
        project_id = request.json.get("project_id")
        tasks_id = request.json.get('tasks_id')
        if not (project_id and tasks_id):
            return make_response({"status": False,
                                  "message": "Missing params"}, 400)
        cursorObject.execute(query.userEmailExist.format(email=email))
        get_data = cursorObject.fetchone()
        __user_id__ = get_data['user_id']
        # company_name = get_data['company_name']
        cursorObject.execute(query.getUserAccessLevel.format(user_id=__user_id__))
        get_data = cursorObject.fetchone()
        userAccessLevel = get_data['access_level']
        userAccessLevel = int(userAccessLevel)
        if userAccessLevel == 2:
            cursorObject.execute(query.viewComment.format(
                tasks_id=tasks_id))
            data = cursorObject.fetchall()
            if data is None:
                return make_response({"status": True,
                                      "code": 200,
                                      'message': "Success",
                                      "data": []}, 200)
            return make_response({"status": True,
                                  "code": 200,
                                  'message': "success",
                                  "data": data}, 200)
        else:
            cursorObject.execute(query.getUserProjectRoles.format(user_id=__user_id__, project_id=project_id))
            get_data = cursorObject.fetchall()
            role_id_list = []
            for __role_id__ in get_data:
                role_id = int(__role_id__['role_id'])
                if role_id == 5:
                    role_id_list.append(role_id)
                else:
                    pass
            if len(role_id_list) == 0:
                return make_response({"status": False,
                                      "message": "Sorry you don't have permission to do this operation."},
                                     200)
            if role_id_list[0] == 5:
                cursorObject.execute(query.viewComment.format(
                    tasks_id=tasks_id))
                data = cursorObject.fetchall()
                if data is None:
                    return make_response({"status": True,
                                          "code": 200,
                                          'message': "Success",
                                          "data": []}, 200)
                return make_response({"status": True,
                                      "code": 200,
                                      'message': "success",
                                      "data": data}, 200)
            else:
                return make_response({"status": False,
                                      "message": "Sorry you don't have permission to do this operation."},
                                     200)
    except Exception as e:
        print(e)
        return make_response({"status": False,
                              "msg": f"Something went wrong, {e}"})


@app_api.route('/user/tasks-activity-log', methods=['POST'])
@cross_origin()
@jwt_required()
def user_tasks_activity_log():
    try:
        db = connect()
        cursorObject = db.cursor()
        email = get_jwt_identity()
        project_id = request.json.get("project_id")
        tasks_id = request.json.get('tasks_id')
        if not (project_id and tasks_id):
            return make_response({"status": False,
                                  "message": "Missing params"}, 400)
        cursorObject.execute(query.userEmailExist.format(email=email))
        get_data = cursorObject.fetchone()
        user_id = get_data['user_id']
        cursorObject.execute(query.getUserProjectRoles.format(user_id=user_id, project_id=project_id))
        get_data = cursorObject.fetchall()
        role_id_list = []
        for __role_id__ in get_data:
            role_id = int(__role_id__['role_id'])
            if role_id == 5:
                role_id_list.append(role_id)
            else:
                pass
        if len(role_id_list) == 0:
            return make_response({"status": False,
                                  "message": "Sorry you don't have permission to do this operation."},
                                 200)
        if role_id_list[0] == 5:
            data = []
            cursorObject.execute(query.checkTasksAssignedLog.format(tasks_id=tasks_id))
            get_assigned_log = cursorObject.fetchall()
            for __get_assigned_log__ in get_assigned_log:
                data.append(__get_assigned_log__)
            cursorObject.execute(query.checkTaskStatusLog.format(tasks_id=tasks_id))
            get_status_log = cursorObject.fetchall()
            for __get_status_log__ in get_status_log:
                data.append(__get_status_log__)
            sorted_data = sorted(data, key=lambda x: x['created_at'], reverse=True)
            return make_response({"status": True,
                                  "code": 200,
                                  'message': "Success",
                                  "data": sorted_data}, 200)
        else:
            return make_response({"status": False,
                                  "message": "Sorry you don't have permission to do this operation."},
                                 200)

    except Exception as e:
        print(e)
        return make_response({"status": False,
                              "message": "Something went wrong"}, 500)


@app_api.route('/user/get-project-document-by-id', methods=['POST'])
@cross_origin()
@jwt_required()
def get_project_document_by_id():
    try:
        db = connect()
        cursorObject = db.cursor()
        admin_email = get_jwt_identity()
        project_id = request.json['project_id']
        stored_file_name = request.json.get('stored_file_name')
        if not (project_id and stored_file_name):
            return make_response({"status": False,
                                  "message": "Missing params"}, 400)
        cursorObject.execute(query.userEmailExist.format(email=admin_email))
        get_data = cursorObject.fetchone()
        admin_id = get_data['admin_id']
        company_name = get_data['company_name']
        bucket_name = DevConfig.bucket_name
        folder_name = f'{company_name}'

        expiration = 3600  #
        file_url = s3.generate_presigned_url(
            ClientMethod='get_object',
            Params={'Bucket': bucket_name,
                    'Key': folder_name + '/' + project_id + '/' + "project_files" + '/' + stored_file_name},
            ExpiresIn=expiration
        )
        # print(file_url)
        file_url = file_url.replace("AKIA3P6QUJFK2JCHJLEO", "")
        data = {"project_id": project_id, "file_url": file_url}
        return make_response({"status": True,
                              "code": 200,
                              'message': "uploaded",
                              "data": data}, 200)
    except Exception as e:
        print(e)
        return make_response({"status": False,
                              "message": "Something went wrong"}, 500)


@app_api.route('/user/get-tasks-document-by-id', methods=['POST'])
@cross_origin()
@jwt_required()
def get_tasks_document_by_id():
    try:
        db = connect()
        cursorObject = db.cursor()
        admin_email = get_jwt_identity()
        project_id = request.json['project_id']
        tasks_id = request.json['tasks_id']
        stored_file_name = request.json.get('stored_file_name')
        if not (project_id and stored_file_name):
            return make_response({"status": False,
                                  "message": "Missing params"}, 400)
        cursorObject.execute(query.userEmailExist.format(email=admin_email))
        get_data = cursorObject.fetchone()
        company_name = get_data['company_name']
        bucket_name = DevConfig.bucket_name
        folder_name = f'{company_name}'

        expiration = 3600  #
        file_url = s3.generate_presigned_url(
            ClientMethod='get_object',
            Params={'Bucket': bucket_name,
                    'Key': folder_name + '/' + project_id + '/' + "tasks_files" + '/' + stored_file_name},
            ExpiresIn=expiration
        )
        # print(file_url)
        file_url = file_url.replace("AKIA3P6QUJFK2JCHJLEO", "")
        data = {"project_id": project_id, "file_url": file_url}
        return make_response({"status": True,
                              "code": 200,
                              'message': "uploaded",
                              "data": data}, 200)
    except Exception as e:
        print(e)
        return make_response({"status": False,
                              "message": "Something went wrong"}, 500)


@app_api.route('/user/project-dashboard', methods=['POST'])
@cross_origin()
@jwt_required()
async def user_project_dashboard():
    try:
        db = connect()
        cursorObject = db.cursor()
        admin_email = get_jwt_identity()
        project_id = request.json['project_id']
        if not project_id:
            return make_response({"status": False,
                                  "message": "Missing params"}, 400)
        cursorObject.execute(query.userEmailExist.format(email=admin_email))
        get_data = cursorObject.fetchone()
        user_id = get_data['user_id']
        cursorObject.execute(query.checkProjectMembers.format(project_id=project_id, user_id=user_id))
        project_users = cursorObject.fetchone()
        if project_users is None:
            return make_response({"status": False,
                                  "message": "Sorry you don't have permission to do this operation."}, 500)

        cursorObject.execute(query.totalProjectMember.format(project_id=project_id))
        project_members = cursorObject.fetchone()
        cursorObject.execute(query.totalProjectTechnologies.format(project_id=project_id))
        project_technology = cursorObject.fetchone()
        total_work_log = {}
        cursorObject.execute(query.totalTimeOnProject.format(project_id=project_id))
        get_work_log = cursorObject.fetchall()
        total_project_log = {}
        if len(get_work_log) <= 0:
            total_project_log = {"total_hours": "0.00"}
        else:
            total_time_spent = timedelta()
            for time_spent in get_work_log:
                time_string = time_spent['time_spent']
                hours, minutes = map(int, time_string.split('.'))
                time_delta = timedelta(hours=hours, minutes=minutes)
                total_time_spent += time_delta
                str_total_time = str(total_time_spent)
                time_parts = str_total_time.split(":")
                hour_minute_string = time_parts[0] + "." + time_parts[1]
                data_dict = {"total_hours": hour_minute_string}
                total_work_log.update(data_dict)
                total_project_log.update(data_dict)
            try:
                if "day" or "days" in str(total_work_log['total_hours']):
                    num_days, hours_mins = total_work_log["total_hours"].split(",")
                    hours, mins = hours_mins.split(".")
                    num_days = int(num_days.strip("days").strip())
                    hours = int(hours.strip())
                    mins = int(mins.strip())
                    total_hours = num_days * 24 + hours
                    # total_project_log = total_hours * 60 + mins
                    total_project_log_ = {"total_hours": f"{total_hours}.{mins}"}
                    total_project_log.update(total_project_log_)
            except:
                pass
        cursorObject.execute(query.totalProjectCodeGenerated.format(project_id=project_id))
        code_generated = cursorObject.fetchone()
        cursorObject.execute(query.totalProjectEpic.format(project_id=project_id))
        total_epic = cursorObject.fetchone()
        cursorObject.execute(query.totalProjectStory.format(project_id=project_id))
        total_story = cursorObject.fetchone()
        cursorObject.execute(query.totalProjectTask.format(project_id=project_id))
        total_task = cursorObject.fetchone()
        dashboard_data = [project_members, project_technology, total_project_log,
                          code_generated, total_epic, total_story, total_task]
        cursorObject.execute(query.status_open.format(project_id=project_id))
        open = cursorObject.fetchone()
        cursorObject.execute(query.status_backlog.format(project_id=project_id))
        backlog = cursorObject.fetchone()
        cursorObject.execute(query.status_to_do.format(project_id=project_id))
        to_do = cursorObject.fetchone()
        cursorObject.execute(query.status_under_review.format(project_id=project_id))
        under_review = cursorObject.fetchone()
        cursorObject.execute(query.status_in_progress.format(project_id=project_id))
        in_progress = cursorObject.fetchone()
        cursorObject.execute(query.status_ready_for_qa.format(project_id=project_id))
        ready_for_qa = cursorObject.fetchone()
        cursorObject.execute(query.status_qa_in_progress.format(project_id=project_id))
        qa_in_progress = cursorObject.fetchone()
        cursorObject.execute(query.status_qa_passed.format(project_id=project_id))
        qa_passed = cursorObject.fetchone()
        cursorObject.execute(query.status_blocked.format(project_id=project_id))
        blocked = cursorObject.fetchone()
        cursorObject.execute(query.status_done.format(project_id=project_id))
        done = cursorObject.fetchone()
        tasks_status = [open, backlog, to_do, under_review, in_progress,
                        ready_for_qa, qa_in_progress, qa_passed, blocked, done]
        return make_response({"status": True,
                              "code": 200,
                              'message': "success",
                              "data": {"dashboard": dashboard_data, "tasks_status": tasks_status}
                              }, 200)
    except Exception as e:
        print(e)
        return make_response({"status": False,
                              "message": "Something went wrong"}, 500)


@app_api.route('/task-list-by-status', methods=['POST'])
@cross_origin()
@jwt_required()
def task_list_status():
    try:
        db = connect()
        cursorObject = db.cursor()
        admin_email = get_jwt_identity()
        project_id = request.json.get('project_id')
        status = request.json.get('status')
        if not (project_id and status):
            return make_response({"status": False,
                                  "message": "Missing params"}, 400)
        # cursorObject.execute(query.userEmailExist.format(email=admin_email))
        # get_data = cursorObject.fetchone()
        # user_id = get_data['user_id']
        # cursorObject.execute(query.get_project_users.format(project_id=project_id))
        # project_users = cursorObject.fetchall()
        cursorObject.execute(query.viewTasksListByStatus.format(project_id=project_id, status=status))
        data = cursorObject.fetchall()
        return make_response({"status": True,
                              "code": 200,
                              'message': "uploaded",
                              "data": data}, 200)
    except Exception as e:
        print(e)
        return make_response({"status": False,
                              "message": "Something went wrong"}, 500)