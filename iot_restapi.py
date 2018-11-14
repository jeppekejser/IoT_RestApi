from flask import Flask, request, jsonify, make_response
from flask_restful import Resource, Api, reqparse
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
import datetime
from sqlalchemy import DateTime
import os
import markdown
from flask_cors import CORS
import jwt
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import string
import random

# Adding HTTPS
import ssl
ctx = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
ctx.load_cert_chain('ssl.cert', 'ssl.key')

#Setup
app = Flask(__name__)

api = Api(app)
CORS(app) # Allow data to be accessed across ports

#Secret key generator, Use this to generate a good secret key
def secret_key_generator(size=256, chars=string.ascii_uppercase + string.ascii_lowercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))

#Secret key
app.config['SECRET_KEY'] = 'This_Should_Really_Be_A_Better_Key'

#Database setup
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'api-database.db')
db = SQLAlchemy(app)
ma = Marshmallow(app)

#Routes
@app.route("/")
def index():
    with open(os.path.join(basedir) + '/index.html', 'r') as markdown_file:

        content = markdown_file.read()

        return markdown.markdown(content)


@app.route("/login")
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('No user with given username/password was found', 401, {'WWW-Authenticate' : 'Basic realm="Login required to access"'})
    
    user = Users.query.filter_by(name=auth.username).first()

    if not user:
        return make_response('No user with given username was found', 401, {'WWW-Authenticate' : 'Basic realm="User not found"'})

    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'public_id' : user.public_id,'user' : auth.username}, app.config['SECRET_KEY'])
        return jsonify({'token' : token.decode('UTF-8')})
    
    return make_response('Could not verify user', 401, {'WWW-Authenticate' : 'Basic realm="Login required to access"'})
    

#Databases
class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(128), unique=True)
    name = db.Column(db.String(50))
    password = db.Column(db.String(80))
    admin = db.Column(db.Boolean)

class UserDataSchema(ma.Schema):
    class Meta:
        fields = ('public_id', 'name', 'password', 'admin')

user_data_schema = UserDataSchema()
all_users_data_schema = UserDataSchema(many=True)

class SensorData(db.Model):
    obs_number = db.Column(db.Integer, primary_key=True)
    dustData = db.Column(db.Float, unique=False)
    co2Data = db.Column(db.Float, unique=False)
    humidityData = db.Column(db.Float, unique=False)
    timeStamp = db.Column(DateTime, default=datetime.datetime.utcnow)

    def __init__(self, dustData, co2Data, humidityData):
        self.dustData = dustData
        self.co2Data = co2Data
        self.humidityData = humidityData


class SensorDataSchema(ma.Schema):
    class Meta:
        fields = ('obs_number', 'dustData', 'co2Data', 'humidityData', 'timeStamp') # Include only the columns that you want to be accesible from GET


sensor_data_schema = SensorDataSchema()
all_sensor_data_schema = SensorDataSchema(many=True)


#Token required function
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message' : 'Token is missing'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = Users.query.filter_by(public_id=data['public_id']).first()
        
        except:
            return jsonify({'message' : 'Token is invalid'}), 401

        return f(current_user, *args, **kwargs)
    
    return decorated


#API methods and endpoints
@app.route('/data', methods=['GET'])
@token_required
def get_all_sensor_data(current_user):
    all_data = SensorData.query.all()
    result = all_sensor_data_schema.dump(all_data)

    return jsonify(result.data)

@app.route('/data', methods=['post'])
@token_required
def add_new_sensor_data(current_user):

    if not current_user.admin:
        return jsonify({'message' : 'You do not have access to that function'})

    dustData = request.json['dustData']
    co2Data = request.json['co2Data']
    humidityData = request.json['humidityData']

    new_data = SensorData(dustData, co2Data, humidityData)

    db.session.add(new_data)
    db.session.commit()

    data = SensorData.query.get(new_data.obs_number)

    return sensor_data_schema.jsonify(data)

@app.route('/users', methods=['GET'])
@token_required
def get_all_users(current_user):

    if not current_user.admin:
        return jsonify({'message' : 'You do not have access to that function'})

    all_users = Users.query.all()
    result = all_users_data_schema.dump(all_users)

    return jsonify(result.data)

@app.route('/users', methods=['POST'])
@token_required
def add_new_user(current_user):

    if not current_user.admin:
        return jsonify({'message' : 'You do not have access to that function'})

    data = request.get_json()

    hash_pass = generate_password_hash(data['password'], method='sha256')

    new_user = Users(public_id=str(uuid.uuid4()), name=data['name'], password=hash_pass, admin=False)

    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message' : 'New user has been created'})


# Users by public_id
@app.route('/users/<public_id>', methods=['GET'])
@token_required
def get_user_by_public_id(current_user, public_id):

    if not current_user.admin:
        return jsonify({'message' : 'You do not have access to that function'})

    user = Users.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message' : 'No user was found with the id: ' + public_id})
    
    result = user_data_schema.dump(user)

    return jsonify(result.data)

@app.route('/users/<public_id>', methods=['PUT'])
@token_required
def promote_user(current_user, public_id):

    if not current_user.admin:
        return jsonify({'message' : 'You do not have access to that function'})

    user = Users.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message' : 'No user was found with the id: ' + public_id})
    
    user.admin = True
    db.session.commit()

    return jsonify({'message' : 'User has been promoted to admin'})

@app.route('/users/<public_id>', methods=['DELETE'])
@token_required
def delete_user(current_user, public_id):

    if not current_user.admin:
        return jsonify({'message' : 'You do not have access to that function'})

    user = Users.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message' : 'No user was found with the id: ' + public_id})

    db.session.delete(user)
    db.session.commit()

    return jsonify({'message' : 'User has been deleted'})

if __name__ == '__main__':
    app.run(debug=False, ssl_context=ctx)
