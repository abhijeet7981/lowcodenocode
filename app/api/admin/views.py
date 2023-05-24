import os
import string
import uuid
from datetime import timedelta
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
from app.api.admin import admin_app_api
from db.databaseConnect import connect
from app.api.admin import query
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
# sender_email = "info@futurework.land"
# s3 = boto3.client('s3', region_name=os.getenv('REGION'),
#                   aws_access_key_id=os.getenv('AWS_ACCESS_KEY'),
#                   aws_secret_access_key=os.getenv("AWS_SECRET_KEY"), config=Config(signature_version='s3v4'))

openai.api_key = DevConfig.open_api_key
s3 = DevConfig.s3
sender_email = DevConfig.sender_email
valid_admin_email = DevConfig.valid_admin_email


@admin_app_api.route('/admin/register', methods=['POST'])
@cross_origin()
def admin_register():
    db = connect()
    try:
        email = request.json.get('email', None)
        name = request.json.get('name', None)
        password = request.json.get('password', None)
        access_level = 1
        company_name = request.json.get('company_name', None)

        if not email:
            return make_response({"status": False,
                                  "message": "Missing email"}, 400)
        if not name:
            return make_response({"status": False,
                                  "message": "Missing Password"}, 400)
        if not password:
            return make_response({"status": False,
                                  "message": "Missing password. Length must must be more than 8 characters"}, 400)
        if len(password) < 8:
            return make_response({"status": False,
                                  "message": "Error, Length must must be more than 8 characters"}, 400)
        if not company_name:
            return make_response({"status": False,
                                  "message": "Missing company Name"}, 200)
        if not access_level:
            return make_response({"status": False,
                                  "message": "Missing access level"}, 400)

        name = name.strip()
        email = email.strip()
        company_name = company_name.strip()
        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        cursorObject = db.cursor()
        emailCheck = cursorObject.execute(query.checkEmail.format(email=email))
        # print(emailCheck)
        if emailCheck >= 1:
            db.rollback()
            return make_response({"status": False,
                                  "message": "Email already exists"}, 200)
        else:
            bucket_name = DevConfig.bucket_name
            folder_name = f'{company_name}/'
            response = s3.list_objects_v2(Bucket=bucket_name, Prefix=folder_name)
            if 'Contents' in response:
                is_verified = 0
                unique_id = uuid.uuid4()
                admin_id = str(unique_id)
                cursorObject.execute(query.register_admin_user.format(
                    admin_id=admin_id,
                    name=name,
                    email=email,
                    password=hashed,
                    access_level=access_level,
                    is_verified=is_verified,
                    company_name=company_name
                ))
                db.commit()
                return make_response(
                    {"status": True,
                     "message": "Success"}, 201)
            else:
                is_verified = 0
                unique_id = uuid.uuid4()
                admin_id = str(unique_id)
                s3.put_object(Bucket=bucket_name, Key=folder_name)
                cursorObject.execute(query.register_admin_user.format(
                    admin_id=admin_id,
                    name=name,
                    email=email,
                    password=hashed,
                    access_level=access_level,
                    is_verified=is_verified,
                    company_name=company_name
                ))
                cursorObject.execute(query.insertBucket.format(
                    admin_id=admin_id,
                    company_name=company_name
                ))
                db.commit()
                return make_response(
                    {"status": True,
                     "message": "Success"}, 201)

    except IntegrityError:
        db.rollback()
        return make_response({"status": False,
                              "message": "Email already exists"}, 200)
    except AttributeError as e:
        return make_response({"status": False,
                              "message": f"Provide request in JSON format only, {e}"}, 400)


@admin_app_api.route('/admin/send-verification-email', methods=["POST", "GET"])
@cross_origin()
def send_verification_email():
    try:
        email = request.json.get('email')
        if not email:
            return make_response(
                {"status": False,
                 "message": "Missing email"}, 400)
        try:
            db = connect()
            cursorObject = db.cursor()
            cursorObject.execute(query.checkEmail.format(email=email))
            fetch = cursorObject.fetchone()
            getEmail = fetch['email']
            getName = fetch['name']
            if email == getEmail:
                oneTimePassword = custom.generate_otp()
                # oneTimePassword = str(oneTimePassword)
                hashed = bcrypt.hashpw(oneTimePassword.encode('utf-8'), bcrypt.gensalt())
                cursorObject.execute(query.addOtp.format(email=email, temp_code=hashed))
                db.commit()
                message = Mail(
                    from_email=sender_email,
                    to_emails=["anirban.d@utahtechlab.com", "jay@utahtechlabs.com"],
                    subject='OTP from Low Code No Code',
                    html_content=render_template('admin_verify.html', getName=getName, email=email,
                                                 oneTimePassword=oneTimePassword))
                sg = SendGridAPIClient(os.environ.get('SENDGRID_API_KEY'))
                sg.send(message)
                return make_response(
                    {"status": True,
                     "code": 200,
                     "message": f"Mail has been sent to Admin for verification. "
                                f"Please contact Admin for OTP."}, 200)
            else:
                return make_response({"status": False,
                                      "message": "User Not registered."}, 200)
        except Exception as e:
            # print(e)
            return make_response({"status": False,
                                  "message": "User Not Registered."}, 200)
    except:
        return make_response({"status": False,
                              "message": "Something went wrong."}, 500)


@admin_app_api.route('/admin/validate-verification-email', methods=["POST"])
@cross_origin()
def validate_verification_email():
    try:
        email = request.json.get('email')
        user_otp = request.json.get('otp')
        if not email:
            return make_response(
                {"status": False,
                 "message": "Missing email"}, 400)
        if not user_otp:
            return make_response(
                {"status": False,
                 "message": "Missing OTP"}, 400)
        userEnterOtp = user_otp.encode("utf-8")
        db = connect()
        cursorObject = db.cursor()
        cursorObject.execute(query.checkEmail.format(email=email))
        fetch = cursorObject.fetchone()
        # print(fetch)
        passwordByUser = fetch["temp_code"].strip("b")
        passwordByUser = passwordByUser.replace("'", "")
        passwordByUser = passwordByUser.encode("utf-8")
        # print(passwordByUser)
        if bcrypt.checkpw(userEnterOtp, passwordByUser) and email == fetch["email"]:
            isVerified = 1
            cursorObject.execute(query.verifyAdmin.format(email=email, is_verified=isVerified))
            db.commit()
            return make_response({"status": True,
                                  "code": 200,
                                  "message": "Success. Email  verification is  successful."}, 200)
        else:
            return make_response({"status": False,
                                  "message": "Failure, OTP does not match."}, 200)
    except:
        return make_response({"status": False,
                              "message": "Something went wrong"}, 500)


@admin_app_api.route('/admin/login', methods=['POST'])
@cross_origin()
def admin_login():
    db = connect()
    try:
        email = request.json.get('email', None)
        password = request.json.get('password', None)

        if not email:
            return make_response({"status": False,
                                  "message": "Missing email"}, 400)
        # if not password:
        #     return make_response({"status": False,
        #                           "message": "Missing Password"}, 400)

        userEnterPassword = password.encode("utf-8")
        cursorObject = db.cursor()
        cursorObject.execute(query.checkEmail.format(email=email))
        fetch = cursorObject.fetchone()
        # print(fetch)
        try:
            admin_id = fetch["admin_id"]
            is_verified = fetch["is_verified"]
            name = fetch['name']
            company_name = fetch['company_name']
            access_level = fetch['access_level']

            if is_verified == 1:
                # print(adminID)
                passwordByUser = fetch["password"].strip("b")
                passwordByUser = passwordByUser.replace("'", "")
                passwordByUser = passwordByUser.encode("utf-8")
                db.commit()
                db.close()
                if bcrypt.checkpw(userEnterPassword, passwordByUser) and email == fetch["email"]:
                    # session['logged_in'] = True
                    access_token = create_access_token(identity=email)
                    refresh_token = create_refresh_token(identity=email)
                    data = {"admin_id": admin_id,
                            "name": name,
                            "company_name": company_name,
                            "access_token": access_token,
                            "refresh_token": refresh_token,
                            "access_level": access_level
                            }
                    return make_response({"status": True,
                                          "code": 200,
                                          "message": "Login Succeeded!",
                                          "data": data}, 200)
                else:
                    return make_response({"status": False,
                                          "message": "Login Failed. Incorrect Email or Password"}, 200)
            else:
                return make_response({"status": False,
                                      "message": "Email verification pending"}, 200)
        except:
            return make_response({"status": False,
                                  "message": "Login failed. Incorrect Email or Password"}, 200)
    except AttributeError as e:
        return make_response({"status": False,
                              "message": f'Provide an Email and Password in JSON format in the request body, {e}'}, 400)


@admin_app_api.route('/admin/forgot-password', methods=['POST'])
@cross_origin()
def admin_forgotPassword():
    db = connect()
    try:
        email = request.json.get('email', None)

        if not email:
            return make_response({"status": False,
                                  "message": "Missing email"}, 400)

        cursorObject = db.cursor()
        cursorObject.execute(query.checkEmail.format(email=email))
        fetch = cursorObject.fetchone()
        try:
            is_verified = fetch["is_verified"]
            email = fetch['email']
            if is_verified == 1:
                oneTimePassword = custom.generate_otp()
                oneTimePassword = str(oneTimePassword)
                hashed = bcrypt.hashpw(oneTimePassword.encode('utf-8'), bcrypt.gensalt())
                cursorObject.execute(query.addOtp.format(email=email, temp_code=hashed))
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


@admin_app_api.route('/admin/change-forgot-password', methods=["POST"])
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
        cursorObject.execute(query.checkEmail.format(email=email))
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
            cursorObject.execute(query.adminResetPassword.format(
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


@admin_app_api.route('/admin/reset-password', methods=['POST'])
@cross_origin()
@jwt_required()
def admin_reset_password():
    try:
        email = request.json.get('email')
        password = request.json.get('password')
        newPassword = request.json.get('newPassword')
        if not email:
            return make_response({"status": False,
                                  "message": "Missing email"}, 400)
        if not password:
            return make_response({"status": False,
                                  "message": "Missing Password"}, 400)
        if not newPassword:
            return make_response({"status": False,
                                  "message": "Missing New Password"}, 400)
        if email == get_jwt_identity():
            userEnterPassword = password.encode("utf-8")
            db = connect()
            cursorObject = db.cursor()
            cursorObject.execute(query.checkEmail.format(email=email))
            fetch = cursorObject.fetchone()

            passwordByUser = fetch["password"].strip("b")
            passwordByUser = passwordByUser.replace("'", "")
            passwordByUser = passwordByUser.encode("utf-8")
            if bcrypt.checkpw(userEnterPassword, passwordByUser) and email == fetch["email"]:
                if len(newPassword) < 8:
                    return make_response({"status": False,
                                          "message": "Error, Length must must be more than 8 characters"}, 400)
                hashed = bcrypt.hashpw(newPassword.encode('utf-8'), bcrypt.gensalt())
                cursorObject.execute(query.adminResetPassword.format(email=email, password=hashed))
                db.commit()
                return make_response({"status": True,
                                      "statusCode": 200,
                                      "message": "Success, Password changed successfully"}, 200)
            else:
                return make_response({"status": False,
                                      "message": "Error, Password doesn't match."}, 200)
        else:
            return make_response({"status": False,
                                  "message": "Unauthorised Email"}, 200)
    except Exception as e:
        # print(e)
        return make_response({"status": False,
                              "message": "Something went wrong"}, 500)


@admin_app_api.route('/admin/add-user', methods=['POST'])
@cross_origin()
@jwt_required()
def admin_add_user():
    admin_email = get_jwt_identity()
    name = request.json.get('name')
    email = request.json.get('email')
    access_level = request.json.get('access_level')

    if not admin_email:
        return make_response({"status": False,
                              "message": "Missing admin email"}, 400)
    if not name:
        return make_response({"status": False,
                              "message": "Missing User name"}, 400)
    if not access_level:
        return make_response({"status": False,
                              "message": "Missing AccessLevel"}, 400)
    if not email:
        return make_response({"status": False,
                              "message": "Missing User email"}, 400)

    name = name.strip()
    password = custom.generate_password()

    try:
        base64EncodedStr = base64.b64encode(password.encode('utf-8'))
        base64.b64decode(base64EncodedStr)
        db = connect()
        cursorObject = db.cursor()
        try:
            cursorObject.execute(query.adminVerified.format(admin_email=admin_email))
            checkAdminEmail = cursorObject.fetchone()
            __admin_email__ = checkAdminEmail['email']
            admin_id = checkAdminEmail['admin_id']
            company_name = checkAdminEmail['company_name']
            # print(adminEmail)
            try:
                if admin_email == __admin_email__:
                    emailCheck = cursorObject.execute(query.userEmailExist.format(email=email))
                    # print(emailCheck)
                    if emailCheck >= 1:
                        db.rollback()
                        return make_response({"status": False,
                                              "message": "Email already exists"}, 200)
                    else:
                        is_verified = 0
                        unique_id = uuid.uuid4()
                        user_id = str(unique_id)
                        cursorObject.execute(query.register_users.format(
                            user_id=user_id,
                            name=name,
                            email=email,
                            password=base64EncodedStr,
                            access_level=access_level,
                            is_verified=is_verified,
                            company_name=company_name,
                            admin_id=admin_id
                        ))
                        db.commit()
                        return make_response({"message": "User Added",
                                              "status": True,
                                              "code": 200}, 200)
                else:
                    return make_response({"status": False,
                                          "message": "Something Went Wrong. This is not an admin account."}, 200)
            except:
                return make_response({"status": False,
                                      "message": "Something Went Wrong. This is not an admin account."}, 200)
        except:
            return make_response({"status": False,
                                  "message": "Something Went Wrong. Admin Email is not valid."}, 200)

    except:
        return make_response({"status": False,
                              "message": "Admin is not verified."}, 200)


@admin_app_api.route('/admin/view-all-users', methods=['GET'])
@cross_origin()
@jwt_required()
def admin_view_all_users():
    try:
        db = connect()
        cursorObject = db.cursor()
        admin_email = get_jwt_identity()
        cursorObject.execute(query.checkEmail.format(email=admin_email))
        get_data = cursorObject.fetchone()
        company_name = get_data['company_name']
        cursorObject.execute(query.admin_view_users.format(company_name=company_name))
        user_data = cursorObject.fetchall()
        cursorObject.execute(query.admin_view_admin_users.format(company_name=company_name))
        admin_data = cursorObject.fetchall()
        data = {"user_data": user_data, "admin_data": admin_data}
        return make_response({"status": True,
                              "code": 200,
                              'message': "Success",
                              "data": data}, 200)
    except Exception as e:
        return make_response({"status": False,
                              "message": "Something went wrong"}, 500)


@admin_app_api.route('/admin/edit-users', methods=['POST'])
@cross_origin()
@jwt_required()
def admin_edit_users():
    try:
        db = connect()
        cursorObject = db.cursor()
        admin_email = get_jwt_identity()
        user_id = request.json.get('user_id')
        cursorObject.execute(query.checkEmail.format(email=admin_email))
        get_data = cursorObject.fetchone()
        company_name = get_data['company_name']
        cursorObject.execute(query.checkUserEmailById.format(user_id=user_id))
        user_data = cursorObject.fetchone()
        access_level = request.json.get('access_level') or user_data['access_level']
        user_name = request.json.get('name') or user_data['name']
        is_banned = request.json.get('is_banned') or user_data['is_banned']
        cursorObject.execute(query.update_users.format(company_name=company_name, user_id=user_id,
                                                       is_banned=is_banned,
                                                       access_level=access_level, name=user_name))
        db.commit()
        return make_response({"status": True,
                              "code": 200,
                              'message': "updated"}, 200)
    except Exception as e:
        return make_response({"status": False,
                              "message": "Something went wrong"}, 500)


@admin_app_api.route('/admin/delete-users', methods=['DELETE'])
@cross_origin()
@jwt_required()
def admin_delete_users():
    try:
        db = connect()
        cursorObject = db.cursor()
        admin_email = get_jwt_identity()
        user_id = request.json.get('user_id')
        cursorObject.execute(query.checkEmail.format(email=admin_email))
        get_data = cursorObject.fetchone()
        company_name = get_data['company_name']
        cursorObject.execute(query.delete_users.format(company_name=company_name, user_id=user_id))
        db.commit()
        return make_response({"status": True,
                              "code": 200,
                              'message': "deleted"}, 200)
    except Exception as e:
        print(e)
        return make_response({"status": False,
                              "message": "Something went wrong"}, 500)


@admin_app_api.route('/admin/add-project', methods=['POST'])
@cross_origin()
@jwt_required()
def admin_add_projects():
    try:
        unique_id = uuid.uuid4()
        db = connect()
        cursorObject = db.cursor()
        admin_email = get_jwt_identity()
        project_id = str(unique_id)
        project_name = request.json.get('project_name')
        project_description = request.json.get('project_description')
        project_url = request.json.get('project_url')
        cursorObject.execute(query.checkEmail.format(email=admin_email))
        get_data = cursorObject.fetchone()
        admin_id = get_data['admin_id']
        cursorObject.execute(query.create_project.format(
            project_id=project_id,
            project_name=project_name,
            project_description=project_description,
            project_url=project_url,
            admin_id=admin_id
        ))
        db.commit()
        data = {"project_id": project_id, "project_name": project_name}
        return make_response({"status": True,
                              "code": 200,
                              'message': "Project Created",
                              "data": data}, 200)
    except Exception as e:
        print(e)
        return make_response({"status": False,
                              "message": "Something went wrong"}, 500)


@admin_app_api.route('/admin/edit-project', methods=['POST'])
@cross_origin()
@jwt_required()
def admin_edit_projects():
    try:
        db = connect()
        cursorObject = db.cursor()
        admin_email = get_jwt_identity()
        project_id = request.json.get('project_id')
        cursorObject.execute(query.checkProjectDetails.format(project_id=project_id))
        get_project_data = cursorObject.fetchone()
        project_name = request.json.get('project_name') or get_project_data['project_name']
        project_description = request.json.get('project_description') or get_project_data['project_description']
        project_url = request.json.get('project_url') or get_project_data['project_url']
        cursorObject.execute(query.checkEmail.format(email=admin_email))
        get_data = cursorObject.fetchone()
        admin_id = get_data['admin_id']
        cursorObject.execute(query.update_project_details.format(
            project_id=project_id,
            project_name=project_name,
            project_description=project_description,
            project_url=project_url,
            admin_id=admin_id
        ))
        db.commit()
        data = {"project_id": project_id, "project_name": project_name}
        return make_response({"status": True,
                              "code": 200,
                              'message': "Project Updated",
                              "data": data}, 200)
    except Exception as e:
        print(e)
        return make_response({"status": False,
                              "message": "Something went wrong"}, 500)


@admin_app_api.route('/admin/add-project-documents', methods=['POST'])
@cross_origin()
@jwt_required()
def admin_add_project_documents():
    try:
        db = connect()
        cursorObject = db.cursor()
        admin_email = get_jwt_identity()
        project_id = request.form['project_id']
        project_attachment = request.files['project_attachment']
        if not (project_id and project_attachment):
            return make_response({"status": False,
                                  "message": "Missing params"}, 400)
        cursorObject.execute(query.checkEmail.format(email=admin_email))
        get_data = cursorObject.fetchone()
        admin_id = get_data['admin_id']
        company_name = get_data['company_name']
        file_name = project_attachment.filename
        unique_id = uuid.uuid4()
        file_unique_name = str(unique_id)
        stored_file_name = file_unique_name + file_name
        bucket_name = DevConfig.bucket_name
        folder_name = f'{company_name}'
        s3.put_object(Body=project_attachment, Bucket=bucket_name,
                      Key=folder_name + '/' + project_id + '/' + "project_files" + '/' + stored_file_name)
        # Company name is set default to Utah Tech Labs
        file_url = "https://lowcodedev.s3.amazonaws.com/Utah+Tech+Labs/" \
                   f"{project_id}/project_files/{stored_file_name}"
        # expiration = 3600  #
        # file_url = s3.generate_presigned_url(
        #     ClientMethod='get_object',
        #     Params={'Bucket': bucket_name,
        #             'Key': folder_name + '/' + project_id + '/' + "project_files" + '/' + stored_file_name},
        #     ExpiresIn=expiration
        # )
        # print(file_url)
        # random_string = ''.join(random.choices(string.ascii_uppercase + string.digits, k=20))

        # Replace access key with random string
        # s3_url = file_url.replace("AKIA3P6QUJFK2JCHJLEO", "")
        cursorObject.execute(query.insertProjectAttachment.format(
            project_id=project_id,
            admin_id=admin_id,
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
    except Exception as e:
        print(e)
        return make_response({"status": False,
                              "message": "Something went wrong"}, 500)


@admin_app_api.route('/admin/delete-project-documents', methods=['DELETE'])
@cross_origin()
@jwt_required()
def admin_delete_project_documents():
    try:
        db = connect()
        cursorObject = db.cursor()
        admin_email = get_jwt_identity()
        project_id = request.json['project_id']
        stored_file_name = request.json.get('stored_file_name')
        if not (project_id and stored_file_name):
            return make_response({"status": False,
                                  "message": "Missing params"}, 400)
        cursorObject.execute(query.checkEmail.format(email=admin_email))
        get_data = cursorObject.fetchone()
        admin_id = get_data['admin_id']
        company_name = get_data['company_name']
        bucket_name = DevConfig.bucket_name
        folder_name = f'{company_name}'
        s3.delete_object(Bucket=bucket_name,
                         Key=folder_name + '/' + project_id + '/' + "project_files" + '/' + stored_file_name)
        cursorObject.execute(query.deleteProjectAttachment.format(
            stored_file_name=stored_file_name
        ))
        db.commit()
        return make_response({"status": True,
                              "code": 200,
                              'message': "deleted"}, 200)
    except Exception as e:
        print(e)
        return make_response({"status": False,
                              "message": "Something went wrong"}, 500)


@admin_app_api.route('/admin/view-project-documents', methods=['POST'])
@cross_origin()
@jwt_required()
def admin_view_project_documents():
    try:
        db = connect()
        cursorObject = db.cursor()
        admin_email = get_jwt_identity()
        project_id = request.json['project_id']
        if not project_id:
            return make_response({"status": False,
                                  "message": "Missing params"}, 400)
        cursorObject.execute(query.checkEmail.format(email=admin_email))
        get_data = cursorObject.fetchone()
        admin_id = get_data['admin_id']
        company_name = get_data['company_name']
        cursorObject.execute(query.getProjectAttachment.format(
            project_id=project_id
        ))
        data = cursorObject.fetchall()
        return make_response({"status": True,
                              "code": 200,
                              'message': "success",
                              "data": data}, 200)
    except Exception as e:
        print(e)
        return make_response({"status": False,
                              "message": "Something went wrong"}, 500)


@admin_app_api.route('/admin/add-project-members', methods=['POST'])
@cross_origin()
@jwt_required()
def admin_add_projects_members():
    try:
        db = connect()
        cursorObject = db.cursor()
        admin_email = get_jwt_identity()
        project_id = request.json.get('project_id')
        user_id = request.json.get('user_id')
        cursorObject.execute(query.checkEmail.format(email=admin_email))
        get_data = cursorObject.fetchone()
        admin_id = get_data['admin_id']
        for __user_id__ in user_id:
            cursorObject.execute(query.create_project_users.format(
                project_id=project_id,
                user_id=__user_id__,
                admin_id=admin_id
            ))
            db.commit()
        return make_response({"status": True,
                              "code": 200,
                              'message': "Users Added"}, 200)
    except Exception as e:
        print(e)
        return make_response({"status": False,
                              "message": "Something went wrong"}, 500)


@admin_app_api.route('/admin/remove-project-members', methods=['POST'])
@cross_origin()
@jwt_required()
def admin_remove_projects_members():
    try:
        db = connect()
        cursorObject = db.cursor()
        admin_email = get_jwt_identity()
        project_id = request.json.get('project_id')
        user_id = request.json.get('user_id')
        cursorObject.execute(query.checkEmail.format(email=admin_email))
        get_data = cursorObject.fetchone()
        admin_id = get_data['admin_id']
        cursorObject.execute(query.remove_project_member.format(
            project_id=project_id,
            user_id=user_id
        ))
        db.commit()
        return make_response({"status": True,
                              "code": 200,
                              'message': "Users Removed"}, 200)
    except Exception as e:
        print(e)
        return make_response({"status": False,
                              "message": "Something went wrong"}, 500)


@admin_app_api.route('/admin/add-project-technology', methods=['POST'])
@cross_origin()
@jwt_required()
def admin_add_projects_technology():
    try:
        db = connect()
        cursorObject = db.cursor()
        admin_email = get_jwt_identity()
        project_id = request.json.get('project_id')
        technology_id = request.json.get('technology_id')
        cursorObject.execute(query.checkEmail.format(email=admin_email))
        get_data = cursorObject.fetchone()
        admin_id = get_data['admin_id']
        for __technology_id__ in technology_id:
            cursorObject.execute(query.create_project_technology.format(
                project_id=project_id,
                technology_id=__technology_id__,
                admin_id=admin_id
            ))
            db.commit()
        return make_response({"status": True,
                              "code": 200,
                              'message': "Technology Added"}, 200)
    except Exception as e:
        print(e)
        return make_response({"status": False,
                              "message": "Something went wrong"}, 500)


@admin_app_api.route('/admin/remove-project-technology', methods=['POST'])
@cross_origin()
@jwt_required()
def admin_remove_projects_technology():
    try:
        db = connect()
        cursorObject = db.cursor()
        admin_email = get_jwt_identity()
        project_id = request.json.get('project_id')
        technology_id = request.json.get('technology_id')
        cursorObject.execute(query.checkEmail.format(email=admin_email))
        get_data = cursorObject.fetchone()
        admin_id = get_data['admin_id']
        cursorObject.execute(query.remove_project_technology.format(
            project_id=project_id,
            technology_id=technology_id
        ))
        db.commit()
        return make_response({"status": True,
                              "code": 200,
                              'message': "Technology Removed"}, 200)
    except Exception as e:
        print(e)
        return make_response({"status": False,
                              "message": "Something went wrong"}, 500)


@admin_app_api.route('/admin/view-projects', methods=['GET'])
@cross_origin()
@jwt_required()
def admin_view_projects():
    try:
        db = connect()
        cursorObject = db.cursor()
        admin_email = get_jwt_identity()
        cursorObject.execute(query.checkEmail.format(email=admin_email))
        get_data = cursorObject.fetchone()
        admin_id = get_data['admin_id']
        company_name = get_data['company_name']
        data = []
        cursorObject.execute(query.get_project_details.format(company_name=company_name))
        project_data_admin = cursorObject.fetchall()
        for k in project_data_admin:
            data.append(k)
        cursorObject.execute(query.get_project_details_users.format(company_name=company_name))
        project_data_admin = cursorObject.fetchall()
        for v in project_data_admin:
            data.append(v)
        sorted_data = sorted(data, key=lambda x: x["created_at"], reverse=True)
        unique_data = [d for i, d in enumerate(sorted_data)
                       if d["project_id"] not in {d["project_id"] for d in sorted_data[i + 1:]}]
        return make_response({"status": True,
                              "code": 200,
                              'message': "Success",
                              "data": unique_data}, 200)
    except Exception as e:
        print(e)
        return make_response({"status": False,
                              "message": "Something went wrong"}, 500)


@admin_app_api.route('/admin/view-projects-by-id', methods=['POST'])
@cross_origin()
@jwt_required()
def admin_view_projects_by_id():
    try:
        db = connect()
        cursorObject = db.cursor()
        admin_email = get_jwt_identity()
        project_id = request.json.get('project_id')
        cursorObject.execute(query.checkEmail.format(email=admin_email))
        get_data = cursorObject.fetchone()
        # admin_id = get_data['admin_id']
        company_name = get_data['company_name']
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


@admin_app_api.route('/admin/add-user-project-roles', methods=['POST'])
@cross_origin()
@jwt_required()
def admin_add_project_users():
    try:
        db = connect()
        cursorObject = db.cursor()
        email = get_jwt_identity()
        project_id = request.json.get('project_id')
        user_id = request.json.get('user_id')
        role_id = request.json.get("role_id")
        for role in role_id:
            cursorObject.execute(query.adminInsertProjectRoles.format(user_id=user_id,
                                                                      project_id=project_id,
                                                                      role_id=role))
            db.commit()
        return make_response({"status": True,
                              "code": 200,
                              'message': "Roles Added"}, 200)
    except Exception as e:
        print(e)
        return make_response({"status": False,
                              "message": "Something went wrong"}, 500)


@admin_app_api.route('/admin/remove-user-project-roles', methods=['POST'])
@cross_origin()
@jwt_required()
def admin_remove_project_users():
    try:
        db = connect()
        cursorObject = db.cursor()
        email = get_jwt_identity()
        project_id = request.json.get('project_id')
        user_id = request.json.get('user_id')
        role_id = request.json.get("role_id")
        cursorObject.execute(query.adminRemoveProjectRoles.format(user_id=user_id,
                                                                  project_id=project_id,
                                                                  role_id=role_id))
        db.commit()
        return make_response({"status": True,
                              "code": 200,
                              'message': "Roles Removed"}, 200)
    except Exception as e:
        print(e)
        return make_response({"status": False,
                              "message": "Something went wrong"}, 500)


@admin_app_api.route('/admin/view-user-project-roles', methods=['POST'])
@cross_origin()
@jwt_required()
def admin_view_project_users_roles():
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


@admin_app_api.route('/admin/view-epic', methods=['POST'])
@cross_origin()
@jwt_required()
def admin_view_epic():
    try:
        db = connect()
        cursorObject = db.cursor()
        email = get_jwt_identity()
        project_id = request.json.get('project_id')
        if not project_id:
            return make_response({"status": False,
                                  "message": "Missing Params"},
                                 200)
        cursorObject.execute(query.viewEpic.format(project_id=project_id))
        data = cursorObject.fetchall()
        return make_response({"status": True,
                              "code": 200,
                              'message': "Success",
                              "data": data}, 200)
    except Exception as e:
        print(e)
        return make_response({"status": False,
                              "message": "Something went wrong"}, 500)


@admin_app_api.route('/admin/view-story', methods=['POST'])
@cross_origin()
@jwt_required()
def admin_view_story():
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
        cursorObject.execute(query.viewStory.format(project_id=project_id, epic_id=epic_id))
        data = cursorObject.fetchall()
        return make_response({"status": True,
                              "code": 200,
                              'message': "Success",
                              "data": data}, 200)
    except Exception as e:
        print(e)
        return make_response({"status": False,
                              "message": "Something went wrong"}, 500)


@admin_app_api.route('/admin/view-task', methods=['POST'])
@cross_origin()
@jwt_required()
def admin_view_task():
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
        cursorObject.execute(query.viewTasks.format(project_id=project_id, story_id=story_id))
        data = cursorObject.fetchall()
        return make_response({"status": True,
                              "code": 200,
                              'message': "Success",
                              "data": data}, 200)
    except Exception as e:
        print(e)
        return make_response({"status": False,
                              "message": "Something went wrong"}, 500)


@admin_app_api.route('/admin/view-task-by-id', methods=['POST'])
@cross_origin()
@jwt_required()
def admin_view_task_by_id():
    try:
        db = connect()
        cursorObject = db.cursor()
        email = get_jwt_identity()
        tasks_id = request.json.get('tasks_id')
        if not tasks_id:
            return make_response({"status": False,
                                  "message": "Missing Params"},
                                 200)
        cursorObject.execute(query.viewTaskById.format(tasks_id=tasks_id))
        data = cursorObject.fetchall()
        return make_response({"status": True,
                              "code": 200,
                              'message': "Success",
                              "data": data}, 200)
    except Exception as e:
        print(e)
        return make_response({"status": False,
                              "message": "Something went wrong"}, 500)


@admin_app_api.route('/admin/create-epic', methods=['POST'])
@cross_origin()
@jwt_required()
def admin_create_epic():
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
        cursorObject.execute(query.checkEmail.format(email=email))
        get_data = cursorObject.fetchone()
        admin_id = get_data['admin_id']
        cursorObject.execute(query.insertEpic.format(epic_id=epic_id,
                                                     project_id=project_id,
                                                     admin_id=admin_id,
                                                     epic_subject=epic_subject,
                                                     epic_description=epic_description))
        db.commit()
        return make_response({"status": True,
                              "code": 200,
                              'message': "Success"}, 200)
    except Exception as e:
        print(e)
        return make_response({"status": False,
                              "message": "Something went wrong"}, 500)


@admin_app_api.route('/admin/update-epic', methods=['POST'])
@cross_origin()
@jwt_required()
def admin_update_epic():
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

    except Exception as e:
        print(e)
        return make_response({"status": False,
                              "message": "Something went wrong"}, 500)


@admin_app_api.route('/admin/create-story', methods=['POST'])
@cross_origin()
@jwt_required()
def admin_create_story():
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
        cursorObject.execute(query.checkEmail.format(email=email))
        get_data = cursorObject.fetchone()
        admin_id = get_data['admin_id']
        cursorObject.execute(query.insertStory.format(story_id=story_id,
                                                      epic_id=epic_id,
                                                      project_id=project_id,
                                                      admin_id=admin_id,
                                                      story_subject=story_subject,
                                                      story_description=story_description))
        db.commit()
        return make_response({"status": True,
                              "code": 200,
                              'message': "Success"}, 200)

    except Exception as e:
        print(e)
        return make_response({"status": False,
                              "message": "Something went wrong"}, 500)


@admin_app_api.route('/admin/update-story', methods=['POST'])
@cross_origin()
@jwt_required()
def admin_update_story():
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
        cursorObject.execute(query.checkEmail.format(email=email))
        get_data = cursorObject.fetchone()
        admin_id = get_data['admin_id']
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

    except Exception as e:
        print(e)
        return make_response({"status": False,
                              "message": "Something went wrong"}, 500)


@admin_app_api.route('/admin/create-task', methods=['POST'])
@cross_origin()
@jwt_required()
def admin_create_task():
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
        if not (project_id and story_id and task_subject and task_description and priority):
            return make_response({"status": False,
                                  "message": "Missing Params"},
                                 200)
        cursorObject.execute(query.checkEmail.format(email=email))
        get_data = cursorObject.fetchone()
        admin_id = get_data['admin_id']
        status = 1
        cursorObject.execute(query.insertTask.format(story_id=story_id,
                                                     tasks_id=tasks_id,
                                                     project_id=project_id,
                                                     admin_id=admin_id,
                                                     task_subject=task_subject,
                                                     task_description=task_description,
                                                     priority=priority,
                                                     status=status,
                                                     admin_assigned=admin_id,
                                                     estimated_time=estimated_time))
        cursorObject.execute(query.insertTaskAssignee.format(
            tasks_id=tasks_id,
            project_id=project_id,
            admin_id=admin_id
        ))
        cursorObject.execute(query.insertTaskStatusLog.format(
            tasks_id=tasks_id,
            project_id=project_id,
            admin_id=admin_id,
            tasks_status=status
        ))
        db.commit()
        return make_response({"status": True,
                              "code": 200,
                              'message': "Success"}, 200)

    except Exception as e:
        print(e)
        return make_response({"status": False,
                              "message": "Something went wrong"}, 500)


@admin_app_api.route('/admin/update-task', methods=['POST'])
@cross_origin()
@jwt_required()
def admin_update_task():
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
        task_subject = (
            request.json.get("task_subject") or epic_data["task_subject"]
        )
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


@admin_app_api.route('/admin/code-gen', methods=['POST'])
@cross_origin()
@jwt_required()
def admin_code_generation():
    try:
        db = connect()
        cursorObject = db.cursor()
        email = get_jwt_identity()
        tasks_id = request.json.get('tasks_id')
        project_id = request.json.get("project_id")
        code_query = request.json.get('code_query')
        unique_id = uuid.uuid4()
        code_id = str(unique_id)
        cursorObject.execute(query.checkEmail.format(email=email))
        get_data = cursorObject.fetchone()
        admin_id = get_data['admin_id']
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
            admin_id=admin_id,
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
    except Exception as e:
        print(e)
        return make_response({"status": False,
                              "msg": f"Something went wrong, {e}"})


@admin_app_api.route('/admin/view-code-gen', methods=['POST'])
@cross_origin()
@jwt_required()
def admin_view_code_generation():
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


@admin_app_api.route('/admin/code-re-gen', methods=['POST'])
@cross_origin()
@jwt_required()
def admin_code_regeneration():
    try:
        db = connect()
        cursorObject = db.cursor()
        email = get_jwt_identity()
        project_id = request.json.get('project_id')
        code_id = request.json.get('code_id')
        code_query = request.json.get('code_query')
        if not (project_id and code_id and code_query):
            return make_response({"status": False,
                                  "message": "Missing Params"},
                                 200)
        cursorObject.execute(query.checkEmail.format(email=email))
        get_data = cursorObject.fetchone()
        admin_id = get_data['admin_id']
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
    except Exception as e:
        print(e)
        return make_response({"status": False,
                              "msg": f"Something went wrong, {e}"})


@admin_app_api.route('/admin/remove-project', methods=['POST'])
@cross_origin()
@jwt_required()
def admin_remove_project():
    try:
        db = connect()
        cursorObject = db.cursor()
        email = get_jwt_identity()
        project_id = request.json.get('project_id')
        if not project_id:
            return make_response({"status": False,
                                  "message": "Missing Params"},
                                 200)
        cursorObject.execute(query.checkEmail.format(email=email))
        get_data = cursorObject.fetchone()
        admin_id = get_data['admin_id']
        cursorObject.execute(query.deleteProjectID.format(project_id=project_id))
        cursorObject.execute(query.deleteEpic.format(project_id=project_id))
        cursorObject.execute(query.deleteStory.format(project_id=project_id))
        cursorObject.execute(query.deleteTasks.format(project_id=project_id))
        cursorObject.execute(query.deleteProjectMembers.format(project_id=project_id))
        cursorObject.execute(query.deleteProjectUserRoles.format(project_id=project_id))
        db.commit()
        return make_response({"status": True,
                              "code": 200,
                              'message': "Deleted"}, 200)
    except Exception as e:
        print(e)
        return make_response({"status": False,
                              "msg": f"Something went wrong, {e}"})


@admin_app_api.route('/admin/remove-project-story', methods=['POST'])
@cross_origin()
@jwt_required()
def admin_remove_project_epic():
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
        cursorObject.execute(query.checkEmail.format(email=email))
        get_data = cursorObject.fetchone()
        admin_id = get_data['admin_id']
        cursorObject.execute(query.deleteStoryByID.format(project_id=project_id, story_id=story_id))
        cursorObject.execute(query.deleteStoryByTasksID.format(project_id=project_id, story_id=story_id))
        db.commit()
        return make_response({"status": True,
                              "code": 200,
                              'message': "Deleted"}, 200)
    except Exception as e:
        print(e)
        return make_response({"status": False,
                              "msg": f"Something went wrong, {e}"})


@admin_app_api.route('/admin/remove-project-epic', methods=['POST'])
@cross_origin()
@jwt_required()
def admin_remove_project_story():
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
        cursorObject.execute(query.checkEmail.format(email=email))
        get_data = cursorObject.fetchone()
        admin_id = get_data['admin_id']
        cursorObject.execute(query.deleteEpicByID.format(project_id=project_id, epic_id=epic_id))
        cursorObject.execute(query.deleteStoryByEpicID.format(project_id=project_id, epic_id=epic_id))
        db.commit()
        return make_response({"status": True,
                              "code": 200,
                              'message': "Deleted"}, 200)
    except Exception as e:
        print(e)
        return make_response({"status": False,
                              "msg": f"Something went wrong, {e}"})


@admin_app_api.route('/admin/remove-project-tasks', methods=['POST'])
@cross_origin()
@jwt_required()
def admin_remove_project_tasks():
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
        cursorObject.execute(query.checkEmail.format(email=email))
        get_data = cursorObject.fetchone()
        admin_id = get_data['admin_id']
        cursorObject.execute(query.deleteTasksByID.format(project_id=project_id, tasks_id=tasks_id))
        db.commit()
        return make_response({"status": True,
                              "code": 200,
                              'message': "Deleted"}, 200)
    except Exception as e:
        print(e)
        return make_response({"status": False,
                              "msg": f"Something went wrong, {e}"})


@admin_app_api.route('/admin/change-tasks-assigned', methods=['POST'])
@cross_origin()
@jwt_required()
def admin_change_tasks_assigned():
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
        cursorObject.execute(query.updateTaskAssignee.format(tasks_id=tasks_id, user_assigned=user_assigned))
        cursorObject.execute(query.insertTaskAssigneeUser.format(
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


@admin_app_api.route('/admin/change-tasks-status', methods=['POST'])
@cross_origin()
@jwt_required()
def admin_change_tasks_status():
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
        cursorObject.execute(query.checkEmail.format(email=email))
        get_data = cursorObject.fetchone()
        admin_id = get_data['admin_id']
        cursorObject.execute(query.updateTaskStatus.format(tasks_id=tasks_id, status=status))
        cursorObject.execute(query.insertTaskStatusLog.format(
            tasks_id=tasks_id,
            project_id=project_id,
            admin_id=admin_id,
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


@admin_app_api.route('/admin/add-task-documents', methods=['POST'])
@cross_origin()
@jwt_required()
def admin_add_task_documents():
    try:
        db = connect()
        cursorObject = db.cursor()
        admin_email = get_jwt_identity()
        project_id = request.form['project_id']
        tasks_id = request.form['tasks_id']
        tasks_attachment = request.files['tasks_attachment']
        if not (project_id and tasks_attachment and tasks_id):
            return make_response({"status": False,
                                  "message": "Missing params"}, 400)
        cursorObject.execute(query.checkEmail.format(email=admin_email))
        get_data = cursorObject.fetchone()
        admin_id = get_data['admin_id']
        company_name = get_data['company_name']
        file_name = tasks_attachment.filename
        unique_id = uuid.uuid4()
        file_unique_name = str(unique_id)
        stored_file_name = file_unique_name + file_name
        bucket_name = DevConfig.bucket_name
        folder_name = f'{company_name}'
        s3.put_object(Body=tasks_attachment, Bucket=bucket_name,
                      Key=folder_name + '/' + project_id + '/' + "tasks_files" + '/' + stored_file_name)
        # Company name is set default to Utah Tech Labs
        file_url = "https://lowcodedev.s3.amazonaws.com/Utah+Tech+Labs/" \
                   f"{project_id}/tasks_files/{stored_file_name}"
        cursorObject.execute(query.insertTaskAttachment.format(
            project_id=project_id,
            admin_id=admin_id,
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
    except Exception as e:
        print(e)
        return make_response({"status": False,
                              "message": "Something went wrong"}, 500)


@admin_app_api.route('/admin/delete-task-documents', methods=['DELETE'])
@cross_origin()
@jwt_required()
def admin_delete_task_documents():
    try:
        db = connect()
        cursorObject = db.cursor()
        admin_email = get_jwt_identity()
        project_id = request.json['project_id']
        stored_file_name = request.json.get('stored_file_name')
        if not (project_id and stored_file_name):
            return make_response({"status": False,
                                  "message": "Missing params"}, 400)
        cursorObject.execute(query.checkEmail.format(email=admin_email))
        get_data = cursorObject.fetchone()
        admin_id = get_data['admin_id']
        company_name = get_data['company_name']
        bucket_name = DevConfig.bucket_name
        folder_name = f'{company_name}'
        s3.delete_object(Bucket=bucket_name,
                         Key=folder_name + '/' + project_id + '/' + "tasks_files" + '/' + stored_file_name)
        cursorObject.execute(query.deleteTaskAttachment.format(
            stored_file_name=stored_file_name
        ))
        db.commit()
        return make_response({"status": True,
                              "code": 200,
                              'message': "deleted"}, 200)
    except Exception as e:
        print(e)
        return make_response({"status": False,
                              "message": "Something went wrong"}, 500)


@admin_app_api.route('/admin/view-task-documents', methods=['POST'])
@cross_origin()
@jwt_required()
def admin_view_task_documents():
    try:
        db = connect()
        cursorObject = db.cursor()
        admin_email = get_jwt_identity()
        tasks_id = request.json['tasks_id']
        if not tasks_id:
            return make_response({"status": False,
                                  "message": "Missing params"}, 400)
        cursorObject.execute(query.checkEmail.format(email=admin_email))
        get_data = cursorObject.fetchone()
        admin_id = get_data['admin_id']
        company_name = get_data['company_name']
        cursorObject.execute(query.getTaskAttachment.format(
            tasks_id=tasks_id
        ))
        data = cursorObject.fetchall()
        return make_response({"status": True,
                              "code": 200,
                              'message': "success",
                              "data": data}, 200)
    except Exception as e:
        print(e)
        return make_response({"status": False,
                              "message": "Something went wrong"}, 500)


@admin_app_api.route('/admin/add-comment', methods=['POST'])
@cross_origin()
@jwt_required()
def add_comment():
    try:
        db = connect()
        cursorObject = db.cursor()
        email = get_jwt_identity()
        project_id = request.json.get("project_id")
        tasks_id = request.json.get('tasks_id')
        if not (project_id and tasks_id):
            return make_response({"status": False,
                                  "message": "Missing params"}, 400)
        cursorObject.execute(query.checkEmail.format(email=email))
        get_data = cursorObject.fetchone()
        admin_id = get_data['admin_id']
        # company_name = get_data['company_name']
        manager_comment = request.json.get("manager_comment")
        if not manager_comment or manager_comment is None:
            return make_response({"status": False,
                                  "message": "Missing params"},
                                 200)
        cursorObject.execute(query.insertManagerComment.format(
            admin_id=admin_id, project_id=project_id, tasks_id=tasks_id, manager_comment=manager_comment))
        db.commit()
        return make_response({"status": True,
                              "code": 200,
                              'message': "success"}, 200)
    except Exception as e:
        print(e)
        return make_response({"status": False,
                              "message": "Something went wrong"}, 500)


@admin_app_api.route('/admin/edit-comment', methods=['POST'])
@cross_origin()
@jwt_required()
def admin_edit_comment():
    try:
        db = connect()
        cursorObject = db.cursor()
        email = get_jwt_identity()
        project_id = request.json.get("project_id")
        comment_id = request.json.get('comment_id')
        manager_comment = request.json.get("manager_comment")
        if not (project_id and comment_id):
            return make_response({"status": False,
                                  "message": "Missing params"}, 400)
        cursorObject.execute(query.checkEmail.format(email=email))
        get_data = cursorObject.fetchone()
        __user_id__ = get_data['admin_id']
        if not manager_comment or manager_comment is None:
            return make_response({"status": False,
                                  "message": "Missing params"},
                                 200)
        cursorObject.execute(query.updateManagerComment.format(
            comment_id=comment_id, manager_comment=manager_comment))
        db.commit()
        return make_response({"status": True,
                              "code": 200,
                              'message': "updated"}, 200)

    except Exception as e:
        print(e)
        return make_response({"status": False,
                              "msg": f"Something went wrong, {e}"})


@admin_app_api.route('/admin/delete-comment', methods=['DELETE'])
@cross_origin()
@jwt_required()
def admin_delete_comment():
    try:
        db = connect()
        cursorObject = db.cursor()
        email = get_jwt_identity()
        project_id = request.json.get("project_id")
        comment_id = request.json.get('comment_id')
        if not (project_id and comment_id):
            return make_response({"status": False,
                                  "message": "Missing params"}, 400)
        cursorObject.execute(query.checkEmail.format(email=email))
        get_data = cursorObject.fetchone()
        __user_id__ = get_data['admin_id']
        # company_name = get_data['company_name']
        cursorObject.execute(query.deleteComment.format(
            comment_id=comment_id))
        db.commit()
        return make_response({"status": True,
                              "code": 200,
                              'message': "deleted"}, 200)
    except Exception as e:
        print(e)
        return make_response({"status": False,
                              "msg": f"Something went wrong, {e}"})


@admin_app_api.route('/admin/view-comment', methods=['POST'])
@cross_origin()
@jwt_required()
def admin_view_comment():
    try:
        db = connect()
        cursorObject = db.cursor()
        email = get_jwt_identity()
        project_id = request.json.get("project_id")
        tasks_id = request.json.get('tasks_id')
        if not (project_id and tasks_id):
            return make_response({"status": False,
                                  "message": "Missing params"}, 400)
        cursorObject.execute(query.checkEmail.format(email=email))
        get_data = cursorObject.fetchone()
        __user_id__ = get_data['admin_id']
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
    except Exception as e:
        print(e)
        return make_response({"status": False,
                              "msg": f"Something went wrong, {e}"})


@admin_app_api.route('/admin/total-task-work-log', methods=['POST'])
@cross_origin()
@jwt_required()
def admin_total_task_work_log():
    try:
        db = connect()
        cursorObject = db.cursor()
        email = get_jwt_identity()
        project_id = request.json.get("project_id")
        tasks_id = request.json.get('tasks_id')
        if not (project_id and tasks_id):
            return make_response({"status": False,
                                  "message": "Missing params"}, 400)
        cursorObject.execute(query.checkEmail.format(email=email))
        get_data = cursorObject.fetchone()
        # user_id = get_data['user_id']
        company_name = get_data['company_name']
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
    except Exception as e:
        print(e)
        return make_response({"status": False,
                              "msg": f"Something went wrong, {e}"})


@admin_app_api.route('/admin/task-work-log-by-user', methods=['POST'])
@cross_origin()
@jwt_required()
def admin_task_work_log_user():
    try:
        db = connect()
        cursorObject = db.cursor()
        email = get_jwt_identity()
        project_id = request.json.get("project_id")
        tasks_id = request.json.get('tasks_id')
        if not (project_id and tasks_id):
            return make_response({"status": False,
                                  "message": "Missing params"}, 400)
        cursorObject.execute(query.checkEmail.format(email=email))
        get_data = cursorObject.fetchone()
        # user_id = get_data['user_id']
        company_name = get_data['company_name']
        cursorObject.execute(query.checkTaskByUser.format(tasks_id=tasks_id))
        get_work_log = cursorObject.fetchall()
        return make_response({"status": True,
                              "code": 200,
                              'message': "success",
                              "data": get_work_log}, 200)
    except Exception as e:
        print(e)
        return make_response({"status": False,
                              "msg": f"Something went wrong, {e}"})


@admin_app_api.route('/admin/total-task-work-log-by-user', methods=['POST'])
@cross_origin()
@jwt_required()
def admin_total_task_work_log_user():
    try:
        db = connect()
        cursorObject = db.cursor()
        email = get_jwt_identity()
        project_id = request.json.get("project_id")
        tasks_id = request.json.get('tasks_id')
        user_id = request.json.get('user_id')
        if not (project_id and tasks_id and user_id):
            return make_response({"status": False,
                                  "message": "Missing params"}, 400)
        # cursorObject.execute(query.checkEmail.format(email=email))
        # get_data = cursorObject.fetchone()
        # __user_id__ = get_data['admin_id']
        data = []
        for users in user_id:
            cursorObject.execute(query.checkTaskByUserID.format(tasks_id=tasks_id, user_id=users))
            get_work_log = cursorObject.fetchall()
            time_spent_by_email = collections.defaultdict(timedelta)
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
    except Exception as e:
        print(e)
        return make_response({"status": False,
                              "msg": f"Something went wrong, {e}"})


@admin_app_api.route('/admin/tasks-activity-log', methods=['POST'])
@cross_origin()
@jwt_required()
def admin_task_activity_log():
    try:
        db = connect()
        cursorObject = db.cursor()
        email = get_jwt_identity()
        project_id = request.json.get("project_id")
        tasks_id = request.json.get('tasks_id')
        if not (project_id and tasks_id):
            return make_response({"status": False,
                                  "message": "Missing params"}, 400)
        # cursorObject.execute(query.userEmailExist.format(email=email))
        # get_data = cursorObject.fetchone()
        # __user_id__ = get_data['user_id']
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
                              'message': "success",
                              "data": sorted_data}, 200)
    except Exception as e:
        print(e)
        return make_response({"status": False,
                              "msg": f"Something went wrong, {e}"})


@admin_app_api.route('/admin/get-project-document-by-id', methods=['POST'])
@cross_origin()
@jwt_required()
def admin_get_project_document_by_id():
    try:
        db = connect()
        cursorObject = db.cursor()
        admin_email = get_jwt_identity()
        project_id = request.json['project_id']
        stored_file_name = request.json.get('stored_file_name')
        if not (project_id and stored_file_name):
            return make_response({"status": False,
                                  "message": "Missing params"}, 400)
        cursorObject.execute(query.checkEmail.format(email=admin_email))
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


@admin_app_api.route('/admin/get-tasks-document-by-id', methods=['POST'])
@cross_origin()
@jwt_required()
def admin_get_tasks_document_by_id():
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
        cursorObject.execute(query.checkEmail.format(email=admin_email))
        get_data = cursorObject.fetchone()
        admin_id = get_data['admin_id']
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


@admin_app_api.route('/admin/project-dashboard', methods=['POST'])
@cross_origin()
@jwt_required()
async def admin_project_dashboard():
    try:
        db = connect()
        cursorObject = db.cursor()
        admin_email = get_jwt_identity()
        project_id = request.json['project_id']
        if not project_id:
            return make_response({"status": False,
                                  "message": "Missing params"}, 400)
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