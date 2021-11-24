from flask import Flask, request, jsonify, make_response
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
import jwt
import datetime
import os
from dotenv import load_dotenv
from functools import wraps

app = Flask(__name__)


load_dotenv()
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')


class User:
    def __init__(self, public_id, name, password, admin):
        self.public_id = public_id
        self.name = name
        self.password = password
        self.admin = admin

        id = 0
        public_id = 0
        name = ""
        password = ""
        admin = False


class Item:
    def __init__(self, name, price, store_id):
        self.name = name
        self.price = price
        self.store_id = store_id

        id = 0
        name = ""
        price = 0
        store_id = 0


users = {}
items = {}


@app.route('/register', methods=['POST'])
def signup_user():
    data = request.get_json()

    hashed_password = generate_password_hash(data['password'], method='sha256')

    new_user = User(public_id=str(uuid.uuid4()), name=data['name'], password=hashed_password, admin=False)
    users[new_user.name] = new_user  # Insert into DB simulation
    return jsonify({'message': 'User registered successfully'})


@app.route("/login", methods=['GET'])  # or POST, we arent sure yet
def login_user():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('Auth info not provided', 401, {'www.authentication': 'Login required'})

    user = users.get(auth.username)  # Username is unique and thus it fetches the matching username in the database

    if check_password_hash(user.password, auth.password):
        token = jwt.encode(
            {'public_id': user.public_id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)},
            app.config['SECRET_KEY'], algorithm='HS256')
        return jsonify({'token': token})
    return make_response('Auth info incorrect', 401, {'www.authentication': 'Login failed'})


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
