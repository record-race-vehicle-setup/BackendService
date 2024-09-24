from flask import Flask, request, jsonify, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from flask_migrate import Migrate
from flask_cors import CORS
import boto3
import base64
import json
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature

app = Flask(__name__)
# app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:root@localhost:3306/userdb'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///userdb.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'MY_SECRET_KEY'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = 7200
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

CORS(app, resources={r"/*": {"origins": "http://localhost:3000", "methods": ["GET", "POST", "DELETE"]}})

s3_client = boto3.client(
    's3',
    aws_access_key_id='AKIA2NK3YJGVJGFXUQEY',
    aws_secret_access_key='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',
    region_name='us-east-1'
)


db = SQLAlchemy(app)
migrate = Migrate(app, db)
jwt = JWTManager(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    email = db.Column(db.String(256), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)
    name = db.Column(db.String(256), nullable=True)
    role = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f'<User {self.username}>'

class UserFile(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    userId = db.Column(db.Integer, nullable=False)
    file_name = db.Column(db.String(256), nullable=True)
    file_id = db.Column(db.String(256), nullable=True)
    flow_type = db.Column(db.String(256), nullable=True)
    race_season = db.Column(db.String(256), nullable=False)
    car_name = db.Column(db.String(256), nullable=True)
    car_model = db.Column(db.String(256), nullable=True)
    json_data = db.Column(db.JSON, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f'<User {self.username}>'

with app.app_context():
    db.create_all()

@app.route('/signup', methods=['POST'])
def signup():
    email = request.json.get('email')
    password = request.json.get('password')
    name = request.json.get('userName')

    if not email or not password:
        return jsonify({"msg": "Email and password are required"}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({"msg": "Email already exists"}), 400

    hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
    new_user = User(email=email, password=hashed_password, role='USER', name=name)

    db.session.add(new_user)
    db.session.commit()
    return jsonify({"msg": "User created successfully"}), 201

@app.route('/login', methods=['POST'])
def login():
    email = request.json.get('email')
    password = request.json.get('password')

    user = User.query.filter_by(email=email).first()
    if user and check_password_hash(user.password, password):
        access_token = create_access_token(identity={'userId': user.id})
        return jsonify({
            "access_token": access_token, 
            "userName": "User" if user.name is None or user.name == "" else user.name
        }), 200

    return jsonify({"msg": "Invalid email or password"}), 401

@app.route('/reset/pwd/request', methods=['POST'])
def request_reset_password():
    email = request.json.get('email')
    
    user = User.query.filter_by(email=email).first()
    
    if not user or user is None:
        return jsonify({'message': 'Invalid email'}), 404
    
    token = serializer.dumps(email, salt='password-reset-salt')
    # reset_link = url_for('reset_password', token=token, _external=True)
    
    custom_base_url = "http://localhost:4200"
    relative_reset_link = url_for('reset_password', token=token)
    reset_link = f"{custom_base_url}{relative_reset_link}"

    responseOfEmailSent = send_reset_email(email, reset_link)

    if not responseOfEmailSent or responseOfEmailSent == "FAILURE":
        return jsonify({'message': 'Failed to send password reset link'}), 500
    
    return jsonify({'message': 'Password reset link sent to your email.'}), 200

@app.route('/reset/pwd/<token>', methods=['POST'])
def reset_password(token):
    try:
        email = serializer.loads(token, salt='password-reset-salt', max_age=3600)
        new_password = request.json.get('password')
        
        if not new_password:
            return jsonify({'message': 'Password is required.'}), 400
        
        user = User.query.filter_by(email=email).first()
        
        if not user or user is None:
            return jsonify({'message': 'User not found'}), 404
        
        hashed_password = generate_password_hash(new_password, method='pbkdf2:sha256')
        user.password = hashed_password
        db.session.commit()

        return jsonify({'message': 'Your password has been updated successfully.'}), 200


    except SignatureExpired:
        return jsonify({'message': 'The token has expired.'}), 400
    except BadSignature:
        return jsonify({'message': 'Invalid token.'}), 400
    except Exception as e:
        print(str(e))
        return jsonify({'message': str(e)}), 500


@app.route('/presign/url', methods=['POST'])
@jwt_required()
def protected():
    current_user = get_jwt_identity()
    fileName = request.json.get('fileName')
    fileSize = request.json.get('fileSize')
    fileType = request.json.get('fileType')

    if not fileName and not fileSize and not fileType:
        return jsonify({"msg": "File type, file size, and file name are required"}), 400

    if not fileName.endswith('.json'):
        return jsonify({"msg": "Only JSON file type is supported"}), 400

    if fileType != 'application/json':
        return jsonify({"msg": "Only JSON file type is supported"}), 400

    try:
        presigned_url = s3_client.generate_presigned_url(
            'put_object',
            Params={
                'Bucket': 'race-vehicle-file',
                'Key': base64.b64encode(str(current_user['userId']).encode('utf-8')).decode('utf-8') + '/' + fileName,
                'ContentType': fileType,
                'ContentLength': isinstance(fileSize, int) if fileSize else int(value),
                'Metadata': {
                    'file_name': fileName
                }
            },
            ExpiresIn=300,
            HttpMethod='PUT'
        )
        
        return jsonify({"presigned_url": presigned_url}), 200
    except Exception as e:
        print(str(e))
        return jsonify({"errorMsg": 'Something went wrong please try again later..!'}), 500

@app.route('/upload/data', methods=['POST'])
@jwt_required()
def listBuckets():
    current_user = get_jwt_identity()
    
    flowType = request.json.get('flowType')

    if not flowType:
        return jsonify({"msg": "Flow type is required"}), 400

    raceSeason = request.json.get('raceSeason')
    carName = request.json.get('carName')
    carModel = request.json.get('carModel')

    if not raceSeason:
        return jsonify({"msg": "Race season are required"}), 400
    
    if flowType == 'FILE':
        fileName = request.json.get('fileName')
        fileId = request.json.get('fileId')

        if not fileName.endswith('.json'):
            return jsonify({"msg": "Only JSON file type is supported"}), 400

        try:
            response = s3_client.get_object(
                Bucket='race-vehicle-file',
                Key=base64.b64encode(str(current_user['userId']).encode('utf-8')).decode('utf-8') + '/' + fileName,
                VersionId=fileId
            )    

            data = json.loads(response['Body'].read().decode('utf-8'))
            new_user_file = UserFile(userId=current_user['userId'], file_name=fileName, file_id=fileId, flow_type=flowType, race_season=raceSeason, car_name=carName, car_model=carModel, json_data=data)
            db.session.add(new_user_file)
            db.session.commit()
            
            return jsonify({"msg": "Data Saved Successfully"}), 200
        
        except Exception as e:
            print(str(e))
            return jsonify({"msg": "Failed", "error": str(e)}), 400

    elif flowType == 'MANUAL':
        jsonData = request.json.get('jsonData')

        new_user_file = UserFile(userId=current_user['userId'], flow_type=flowType, race_season=raceSeason, car_name=carName, car_model=carModel, json_data=jsonData)
        db.session.add(new_user_file)
        db.session.commit()

        return jsonify({"msg": "Data Saved Successfully"}), 200

    else:
        return jsonify({"msg": "Invalid flow type"}), 400

@app.route('/all/races', methods=['GET'])
@jwt_required()
def getAllRaces():
    current_user = get_jwt_identity()
    
    query = UserFile.query.with_entities(
        UserFile.id, UserFile.userId, UserFile.file_name, UserFile.file_id, 
        UserFile.flow_type, UserFile.race_season, 
        UserFile.car_name, UserFile.car_model,
        UserFile.created_at, UserFile.updated_at
    )
    
    query = query.filter(UserFile.userId == current_user['userId'])
    user_files = query.all()
    
    files_list = []

    for file in user_files:
        files_list.append({
            'id': file.id,
            'userId': file.userId,
            'file_name': file.file_name,
            'file_id': file.file_id,
            'flow_type': file.flow_type,
            'race_season': file.race_season,
            'car_name': file.car_name,
            'car_model': file.car_model,
            'created_at': file.created_at,
            'updated_at': file.updated_at
        })

    return jsonify(files_list), 200

@app.route('/race/<int:raceId>', methods=['GET'])
@jwt_required()
def getRace(raceId):
    current_user = get_jwt_identity()

    query = UserFile.query.with_entities(
        UserFile.id, UserFile.userId, UserFile.file_name, UserFile.file_id, 
        UserFile.flow_type, UserFile.race_season, 
        UserFile.car_name, UserFile.car_model, UserFile.json_data,
        UserFile.created_at, UserFile.updated_at
    )

    if not raceId:
        return jsonify({"msg": "Race ID is required"}), 400
    
    query = query.filter(UserFile.id == raceId).filter(UserFile.userId == current_user['userId'])
    user_file = query.first()

    if user_file is None:
        return jsonify({'error': 'Data not found'}), 404

    print(user_file)

    file_data = {
        'id': user_file.id,
        'file_name': user_file.file_name,
        'file_id': user_file.file_id,
        'flow_type': user_file.flow_type,
        'race_season': user_file.race_season,
        'car_name': user_file.car_name,
        'car_model': user_file.car_model,
        'json_data': user_file.json_data,
        'created_at': user_file.created_at,
        'updated_at': user_file.updated_at
    }

    return jsonify(file_data), 200


def send_reset_email(email, reset_link):
    smtp_server = 'smtp.gmail.com'
    smtp_port = 587
    smtp_user = 'race.vehicles.setup@gmail.com'
    smtp_password = 'stob rgcz whuo glzv'

    msg = MIMEMultipart()
    msg['From'] = smtp_user
    msg['To'] = email
    msg['Subject'] = 'Password Reset Request'
    
    body = f'Hi, \n\nClick the link below to reset your password:\n{reset_link}\n\nBest regards,\nRace Vehicle Team'
    msg.attach(MIMEText(body, 'plain'))
    
    try:
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(smtp_user, smtp_password)
        server.sendmail(smtp_user, email, msg.as_string())
        server.quit()
        return "SUCCESS"
    except Exception as e:
        print(str(e))
        return "FAILURE"

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5555, debug=True)