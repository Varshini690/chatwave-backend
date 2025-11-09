from flask import Blueprint, request, jsonify
from flask_jwt_extended import create_access_token
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from extensions import mongo, jwt

auth_bp = Blueprint('auth_bp', __name__)  # ✅ keep consistent with app.py import

@auth_bp.route('/register', methods=['POST'])
def register_user():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    if not username or not email or not password:
        return jsonify({'msg': 'Missing required fields'}), 400

    if mongo.db.users.find_one({'email': email}):
        return jsonify({'msg': 'User already exists'}), 409

    hashed_pw = generate_password_hash(password)
    mongo.db.users.insert_one({
        'username': username,
        'email': email,
        'password_hash': hashed_pw,
        'created_at': datetime.utcnow()
    })
    return jsonify({'msg': 'User registered successfully'}), 201


@auth_bp.route('/login', methods=['POST'])
def login_user():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    user = mongo.db.users.find_one({'email': email})
    if not user:
        return jsonify({'msg': 'User not found'}), 404

    if not check_password_hash(user['password_hash'], password):
        return jsonify({'msg': 'Invalid credentials'}), 401

    token = create_access_token(identity=str(user['_id']), expires_delta=timedelta(days=1))

    return jsonify({
        'msg': 'Login successful',
        'token': token,
        'username': user['username']
    }), 200
