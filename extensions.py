# extensions.py

from flask_pymongo import PyMongo
from flask_jwt_extended import JWTManager
from flask_socketio import SocketIO

# Database
mongo = PyMongo()

# JWT for authentication
jwt = JWTManager()

# SocketIO for real-time chat (used by app.py)
socketio = SocketIO(cors_allowed_origins="*")
