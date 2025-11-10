import eventlet
eventlet.monkey_patch()
from datetime import timezone, timedelta
from flask import Flask, request, jsonify
from flask_cors import CORS
from config import Config
from extensions import mongo, jwt
from flask_socketio import SocketIO, emit, join_room
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import create_access_token
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from bson import ObjectId


"""
ChatWave Backend — "Auto-friends + Block + Search" (no friend-requests)
Matches the new Chat.jsx you added.

Key differences vs earlier version:
- Removed friend-requests entirely
- Added HTTP: GET /search_users?q=
- Added sockets: get_lists, auto_add_friend
- send_private_message blocks delivery when either side has blocked the other
- block_user also removes from friends list
- Emits both `lists` and legacy `friend_list` / `blocked_list` for compatibility
"""


# ------------------------------------------------------
# APP FACTORY
# ------------------------------------------------------

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    CORS(
    app,
    resources={r"/*": {
        "origins": [
            "https://chatwave-frontend-r4vwc5v1v-hanis-projects-d61265e6.vercel.app",
            "https://chatwave-backend-9vhe.onrender.com",
            "http://localhost:3000",
            "http://127.0.0.1:3000"
        ]
    }},
    supports_credentials=True,
)


    mongo.init_app(app)
    jwt.init_app(app)
    mail = Mail(app)
    serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"])
    socketio = SocketIO(
    app,
    cors_allowed_origins=[
        "https://chatwave-frontend-r4vwc5v1v-hanis-projects-d61265e6.vercel.app",
        "https://chatwave-backend-9vhe.onrender.com",
        "http://localhost:3000",
        "http://127.0.0.1:3000"
    ],
    async_mode="eventlet",
    ping_timeout=60,
    ping_interval=25
)



    # ------------------------------------------------------
    # AUTO-CREATE MONGO COLLECTIONS & INDEXES
    # ------------------------------------------------------
    with app.app_context():
        db = mongo.db
        for coll in ["users", "messages", "room_messages", "friends", "blocked"]:
            if coll not in db.list_collection_names():
                db.create_collection(coll)
                print(f"🆕 Created MongoDB collection: {coll}")

        # indexes
        db.users.create_index("email", unique=True)
        db.friends.create_index("user", unique=True)
        db.blocked.create_index("user", unique=True)
        db.messages.create_index([("sender", 1), ("receiver", 1), ("timestamp", 1)])
        db.room_messages.create_index([("room", 1), ("timestamp", 1)])

        print("✅ MongoDB collections & indexes verified")

    connected_users = {}
    room_users = {}
    online_status = {}   # username → True/False
    last_seen = {}       # username → datetime


    # ------------------------------------------------------
    # BASIC ROUTE
    # ------------------------------------------------------
    @app.route("/")
    def home():
        return "✅ ChatWave Backend Running (auto-friends + block + search)"

    # ------------------------------------------------------
    # REGISTER & LOGIN
    # ------------------------------------------------------
    @app.route("/register", methods=["POST", "OPTIONS"])
    def register_user():
        if request.method == "OPTIONS":
            return jsonify({"ok": True}), 200

        data = request.get_json() or {}
        username = data.get("username")
        email = data.get("email")
        password = data.get("password")

        if not username or not email or not password:
            return jsonify({"error": "Missing required fields"}), 400

        if mongo.db.users.find_one({"email": email}):
            return jsonify({"error": "User already exists"}), 409

        hashed_pw = generate_password_hash(password)
        mongo.db.users.insert_one({
            "username": username,
            "email": email,
            "password": hashed_pw,
            "created_at": datetime.now(timezone.utc)

        })
        print(f"✅ Registered: {username} ({email})")
        return jsonify({"message": "User registered successfully!"}), 201

    @app.route("/login", methods=["POST", "OPTIONS"])
    def login_user():
        if request.method == "OPTIONS":
            return jsonify({"ok": True}), 200

        data = request.get_json() or {}
        email = data.get("email")
        password = data.get("password")

        user = mongo.db.users.find_one({"email": email})
        if not user or not check_password_hash(user["password"], password):
            return jsonify({"error": "Invalid credentials"}), 401

        token = create_access_token(identity=str(user["_id"]), expires_delta=timedelta(days=1))
        print(f"✅ {user['username']} logged in successfully")
        return jsonify({
            "message": "Login successful!",
            "token": token,
            "username": user["username"],
        }), 200

    # ------------------------------------------------------
    # FORGOT PASSWORD (unchanged)
    # ------------------------------------------------------
    @app.route("/forgot-password", methods=["POST"])
    def forgot_password():
        data = request.get_json() or {}
        email = data.get("email")

        user = mongo.db.users.find_one({"email": email})
        if not user:
            return jsonify({"error": "User not found"}), 404

        token = serializer.dumps(email, salt="password-reset-salt")
        reset_link = f"https://chatwave-frontend-r4vwc5v1v-hanis-projects-d61265e6.vercel.app/reset-password/{token}"


        msg = Message(
            subject="ChatWave Password Reset 🔐",
            sender=app.config["MAIL_DEFAULT_SENDER"],
            recipients=[email],
        )
        msg.html = f"""
            <div style='font-family:Inter,sans-serif;'>
                <h2 style='color:#2563eb;'>Password Reset Request</h2>
                <p>Hello <b>{user['username']}</b>,</p>
                <p>Click below to reset your password.</p>
                <a href='{reset_link}'
                   style='background:#2563eb;color:white;padding:10px 20px;border-radius:8px;text-decoration:none;'>
                   Reset Password
                </a>
                <p style='color:#64748b;'>If you didn’t request this, ignore this email.</p>
            </div>
        """

        mail.send(msg)
        print(f"📧 Reset link sent to {email}")
        return jsonify({"message": "Reset link sent!"}), 200

    @app.route("/reset-password/<token>", methods=["POST"])
    def reset_password(token):
        try:
            email = serializer.loads(token, salt="password-reset-salt", max_age=1800)
        except SignatureExpired:
            return jsonify({"error": "Link expired"}), 400
        except BadSignature:
            return jsonify({"error": "Invalid token"}), 400

        data = request.get_json() or {}
        new_password = data.get("password")
        if not new_password:
            return jsonify({"error": "New password required"}), 400

        hashed_pw = generate_password_hash(new_password)
        mongo.db.users.update_one({"email": email}, {"$set": {"password": hashed_pw}})
        print(f"✅ Password reset for {email}")
        return jsonify({"message": "Password updated successfully!"}), 200

    # ------------------------------------------------------
    # SEARCH USERS (for sidebar search)
    # ------------------------------------------------------
    @app.route("/search_users", methods=["GET"])
    def search_users():
        q = request.args.get("q", "").strip()
        if not q:
            return jsonify([])
        # case-insensitive substring search on username
        cursor = mongo.db.users.find({"username": {"$regex": q, "$options": "i"}}, {"_id": 0, "username": 1})
        users = list(cursor)
        return jsonify(users)
    
    # ------------------------------------------------------
    # 🟢 USER STATUS (Online / Last Seen)
    # ------------------------------------------------------
    @app.route("/status/<username>")
    def get_status(username):
        username = username.lower()  # ✅ normalize to lowercase
        if username in online_status and online_status[username]:
            return jsonify({"status": "online"})
        if username in last_seen:
            diff = datetime.now(timezone.utc)- last_seen[username]
            mins = int(diff.total_seconds() // 60)
            return jsonify({"status": f"last seen {mins} min ago"})
        return jsonify({"status": "offline"})





    # ------------------------------------------------------
    # SOCKET.IO EVENTS
    # ------------------------------------------------------
    @socketio.on("connect")
    def handle_connect():
        print(f"🟢 Connected: {request.sid}")

    # ---------- helpers ----------
    def _get_friends(username: str):
        doc = mongo.db.friends.find_one({"user": username})
        return doc.get("list", []) if doc else []

    def _get_blocked(username: str):
        doc = mongo.db.blocked.find_one({"user": username})
        return doc.get("list", []) if doc else []

    def _either_blocked(a: str, b: str) -> bool:
        # True if a blocked b OR b blocked a
        return b in _get_blocked(a) or a in _get_blocked(b)

    def _emit_lists(username: str):
        friends_list = _get_friends(username)
        blocked_list = _get_blocked(username)
        sid = connected_users.get(username.lower())
        if sid:
            emit("lists", {"friends": friends_list, "blocked": blocked_list}, room=sid)
            # legacy for compatibility
            emit("friend_list", friends_list, room=sid)
            emit("blocked_list", blocked_list, room=sid)

    # ---------- USER REGISTRATION EVENT ----------
    # ---------- USER REGISTRATION EVENT ----------
    @socketio.on("register_user")
    def handle_register_user(data):
        username = (data or {}).get("username")
        if not username:
            return
        uname = username.lower()   # ✅ normalize key
        connected_users[uname] = request.sid
        online_status[uname] = True
        last_seen[uname] = datetime.now(timezone.utc)


        print(f"✅ Registered user: {username} is online")
        emit("user_list", list(connected_users.keys()), broadcast=True)
        _emit_lists(username)

    @socketio.on("get_lists")
    def handle_get_lists(data):
        username = (data or {}).get("username")
        if username:
            _emit_lists(username)

    # ---------- PRIVATE CHAT ----------
    @socketio.on("join_private")
    def handle_join_private(data):
        user1 = (data or {}).get("user1")
        user2 = (data or {}).get("user2")
        if not user1 or not user2:
            return
        room_name = "_".join(sorted([user1.lower(), user2.lower()]))
        join_room(room_name)

        messages = mongo.db.messages.find({
            "$or": [
                {"sender": user1, "receiver": user2},
                {"sender": user2, "receiver": user1},
            ]
        }).sort("timestamp", 1)

        history = [
            {
                "sender": m["sender"],
                "receiver": m["receiver"],
                "message": m["message"],
                "timestamp": m["timestamp"].isoformat(),
                "read": m.get("read", False) 
            }
            for m in messages
        ]
        emit("chat_history", {"user1": user1, "user2": user2, "messages": history}, room=request.sid)

    @socketio.on("send_private_message")
    def handle_private_message(data):
        sender = (data or {}).get("sender", "").strip().lower()
        receiver = (data or {}).get("receiver", "").strip().lower()
        message = (data or {}).get("message", "")
        timestamp = datetime.now(timezone.utc)
        if not sender or not receiver or not message:
            return

        # Block check (either side)
        if _either_blocked(sender, receiver):
            # Inform only the sender
            emit(
                "receive_private_message",
                {
                    "system": True,
                    "message": f"Message not delivered: communication is blocked",
                    "timestamp": timestamp.isoformat(),
                    "sender": sender,
                    "receiver": receiver,
                },
                room=request.sid,
            )
            return

        room_name = "_".join(sorted([sender.lower(), receiver.lower()]))
        join_room(room_name)

        result=mongo.db.messages.insert_one({
            "sender": sender,
            "receiver": receiver,
            "message": message,
            "timestamp": timestamp,
            "read": False   # 👈 Added flag for read receipts
        })
        msg_id = str(result.inserted_id)
        msg_data = {
            "_id": msg_id,
            "sender": sender,
            "receiver": receiver,
            "message": message,
            "timestamp": timestamp.isoformat(),
        }
        emit("receive_private_message", msg_data, room=room_name)
        print(f"💬 {sender} → {receiver}: {message}")

    # ---------- AUTO-ADD FRIENDS ----------
    @socketio.on("auto_add_friend")
    def handle_auto_add_friend(data):
        a = (data or {}).get("a")
        b = (data or {}).get("b")
        if not a or not b:
            return
        mongo.db.friends.update_one({"user": a}, {"$addToSet": {"list": b}}, upsert=True)
        mongo.db.friends.update_one({"user": b}, {"$addToSet": {"list": a}}, upsert=True)
        print(f"🤝 Auto-friended {a} ↔ {b}")
        _emit_lists(a)
        _emit_lists(b)

    # ---------- BLOCK / UNBLOCK ----------
    @socketio.on("block_user")
    def block_user_evt(data):
        blocker = (data or {}).get("blocker")
        blocked = (data or {}).get("blocked")
        if not blocker or not blocked:
            return
        mongo.db.blocked.update_one({"user": blocker}, {"$addToSet": {"list": blocked}}, upsert=True)
        # Also remove from friends on both sides
        mongo.db.friends.update_one({"user": blocker}, {"$pull": {"list": blocked}}, upsert=True)
        mongo.db.friends.update_one({"user": blocked}, {"$pull": {"list": blocker}}, upsert=True)
        print(f"🚫 {blocker} blocked {blocked}")
        _emit_lists(blocker)
        _emit_lists(blocked)

    @socketio.on("unblock_user")
    def unblock_user_evt(data):
        blocker = (data or {}).get("blocker")
        blocked = (data or {}).get("blocked")
        if not blocker or not blocked:
            return
        mongo.db.blocked.update_one({"user": blocker}, {"$pull": {"list": blocked}}, upsert=True)
        print(f"♻️ {blocker} unblocked {blocked}")
        _emit_lists(blocker)

    # ---------- ROOM CHAT ----------
    @socketio.on("join_room")
    def handle_join_room(data):
        username = (data or {}).get("username")
        room = (data or {}).get("room")
        if not username or not room:
            return

        join_room(room)
        room_users.setdefault(room, set()).add(username)

        emit(
            "receive_room_message",
            {
                "system": True,
                "room": room,
                "message": f"{username} joined the room",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
            room=room,
        )

        emit("room_user_list", list(room_users[room]), room=room)

        history = [
            {
                "sender": m["sender"],
                "room": m["room"],
                "message": m["message"],
                "timestamp": m["timestamp"].isoformat(),
            }
            for m in mongo.db.room_messages.find({"room": room}).sort("timestamp", 1)
        ]
        emit("room_history", {"room": room, "messages": history}, room=request.sid)

    @socketio.on("send_room_message")
    def handle_room_message(data):
        sender = (data or {}).get("sender")
        room = (data or {}).get("room")
        message = (data or {}).get("message")
        if not sender or not room or not message:
            return

        timestamp = datetime.now(timezone.utc)

        result= mongo.db.room_messages.insert_one({
            "sender": sender,
            "room": room,
            "message": message,
            "timestamp": timestamp,
        })
        msg_id = str(result.inserted_id)
        emit(
            "receive_room_message",
            {"_id": msg_id, "sender": sender, "message": message, "timestamp": timestamp.isoformat(), "room": room},
            room=room,
        )
        print(f"🏠 {sender}@{room}: {message}")

    # ---------- TYPING ----------
    @socketio.on("typing")
    def handle_typing(data):
        user = (data or {}).get("user")
        receiver = (data or {}).get("receiver")
        if user and receiver:
            emit("user_typing", {"user": user, "receiver": receiver}, broadcast=True)

    # ---------- DISCONNECT ----------
    @socketio.on("disconnect")
    def handle_disconnect():
        disconnected = None
        for user, sid in list(connected_users.items()):
            if sid == request.sid:
                disconnected = user
                del connected_users[user]
                online_status[user.lower()] = False  # ✅ normalize
                last_seen[user.lower()] = datetime.now(timezone.utc)

                break


        if disconnected:
            print(f"🔴 {disconnected} disconnected")
            # Update all rooms the user was in
            for r, users in list(room_users.items()):
                if disconnected in users:
                    users.remove(disconnected)
                    emit("room_user_list", list(users), room=r)
                    emit(
                        "receive_room_message",
                        {
                            "system": True,
                            "room": r,
                            "message": f"{disconnected} left the room",
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                        },
                        room=r,
                    )

            # ✅ Broadcast updated user list
            emit("user_list", list(connected_users.keys()), broadcast=True)
   
    # ------------------------------------------------------
    # 👁️ MARK MESSAGES AS READ (Double Tick)
    # ------------------------------------------------------
    @socketio.on("mark_as_read")
    def mark_as_read(data):
        sender = (data or {}).get("sender")
        receiver = (data or {}).get("receiver")

        if not sender or not receiver:
            return

        # ✅ Mark all unread messages from sender → receiver as read
        mongo.db.messages.update_many(
            {"sender": sender, "receiver": receiver, "read": False},
            {"$set": {"read": True}},
        )

        # ✅ Notify the original sender about read update
        sender_sid = connected_users.get(sender.lower())
        if sender_sid:
            emit("update_read_status", {"sender": sender, "receiver": receiver}, room=sender_sid)

        print(f"👁️ {receiver} has read messages from {sender}")

    # ------------------------------------------------------
    # 🗑️ DELETE MESSAGE (Private & Room)
    # ------------------------------------------------------
    @socketio.on("delete_message")
    def handle_delete_message(data):
        from bson.errors import InvalidId

        msg_id = data.get("msg_id")
        chat_type = data.get("type", "private")
        sender = data.get("sender")
        receiver = data.get("receiver")
        room = data.get("room")

        if not msg_id or not sender:
            print(f"⚠️ Missing msg_id or sender: {data}")
            return

        try:
            obj_id = ObjectId(msg_id)
        except Exception as e:
            print(f"⚠️ Invalid ObjectId {msg_id}: {e}")
            return

        if chat_type == "private":
            result = mongo.db.messages.delete_one({"_id": obj_id})
            if result.deleted_count:
                if receiver:
                    room_name = "_".join(sorted([sender.lower(), receiver.lower()]))
                    emit("message_deleted", {"msg_id": msg_id}, room=room_name)
                    print(f"🗑️ Deleted private message {msg_id} by {sender}")
                else:
                    sid = connected_users.get(sender.lower())
                    if sid:
                        emit("message_deleted", {"msg_id": msg_id}, room=sid)

        elif chat_type == "room":
            result = mongo.db.room_messages.delete_one({"_id": obj_id})
            if result.deleted_count:
                emit("message_deleted", {"msg_id": msg_id, "room": room}, room=room)
                print(f"🗑️ Deleted room message {msg_id}")

        # ------------------------------------------------------
    # 🧹 DELETE ENTIRE PRIVATE CHAT + REMOVE FROM FRIENDS LIST (Case-insensitive + Verified)
    # ------------------------------------------------------
    @socketio.on("delete_chat")
    def handle_delete_chat(data):
        user1 = (data or {}).get("user1", "").strip()
        user2 = (data or {}).get("user2", "").strip()

        if not user1 or not user2:
            print("⚠️ Missing users in delete_chat:", data)
            return

        print(f"🧩 Delete chat requested between '{user1}' and '{user2}'")

        # 🔍 Case-insensitive deletion query
        delete_query = {
            "$or": [
                {
                    "sender": {"$regex": f"^{user1}$", "$options": "i"},
                    "receiver": {"$regex": f"^{user2}$", "$options": "i"},
                },
                {
                    "sender": {"$regex": f"^{user2}$", "$options": "i"},
                    "receiver": {"$regex": f"^{user1}$", "$options": "i"},
                },
            ]
        }

        # 🧠 Debug: print some messages before deletion
        existing = list(mongo.db.messages.find(delete_query))
        print(f"🔍 Found {len(existing)} messages before deletion.")
        if existing:
            print("Example document:", existing[0])

        # ✅ Delete all matching messages
        result = mongo.db.messages.delete_many(delete_query)
        print(f"🧹 Deleted {result.deleted_count} messages between {user1} and {user2}")

        # ✅ Remove each other from friends lists
        mongo.db.friends.update_one({"user": user1}, {"$pull": {"list": user2}}, upsert=True)
        mongo.db.friends.update_one({"user": user2}, {"$pull": {"list": user1}}, upsert=True)

        # ✅ Notify both users’ sockets
        room_name = "_".join(sorted([user1.lower(), user2.lower()]))
        emit("chat_deleted", {"user1": user1, "user2": user2}, room=room_name)

        _emit_lists(user1)
        _emit_lists(user2)


    return app, socketio    

    



# ------------------------------------------------------
# MAIN ENTRY POINT
# ------------------------------------------------------
import os

if __name__ == "__main__":
    app, socketio = create_app()
    print("🚀 Starting ChatWave Backend (Auto-friends + Block + Search)…")
    socketio.run(app, host="0.0.0.0", port=5000)

