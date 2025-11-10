# --- gevent first (no eventlet needed) ---
from gevent import monkey
monkey.patch_all()
from flask_mail import Message
from werkzeug.security import generate_password_hash
from itsdangerous import SignatureExpired, BadSignature

from datetime import timezone, timedelta, datetime
from flask import Flask, request, jsonify
from flask_cors import CORS
from config import Config
from extensions import mongo, jwt
from flask_socketio import SocketIO, emit, join_room
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import create_access_token
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from bson import ObjectId

"""
ChatWave Backend — Auto-friends + Block + Search
- Fully gevent-based (no eventlet)
- Global CORS (fixes /status/<user> & websocket handshakes)
"""

ALLOWED_ORIGINS = [
    "https://chatwave-frontend-psi.vercel.app",
    "https://chatwave-frontend-r4vwc5v1v-hanis-projects-d61265e6.vercel.app",
    "https://chatwave-backend-9vhe.onrender.com",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # ---- Flask-CORS (broad, but we’ll also add a dynamic after_request) ----
    CORS(
        app,
        origins=ALLOWED_ORIGINS,
        supports_credentials=True,
        allow_headers=["Content-Type", "Authorization"],
        methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    )

    # ---- Dynamic CORS for any route (including /status/<user>) ----
    @app.after_request
    def add_cors_headers(response):
        origin = request.headers.get("Origin")
        if origin in ALLOWED_ORIGINS:
            response.headers["Access-Control-Allow-Origin"] = origin
            response.headers["Vary"] = "Origin"
            response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers.setdefault("Access-Control-Allow-Headers", "Content-Type, Authorization")
        response.headers.setdefault("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        return response

    # ---- Init extensions ----
    mongo.init_app(app)
    jwt.init_app(app)
    mail = Mail(app)
    serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"])

    socketio = SocketIO(
        app,
        cors_allowed_origins=ALLOWED_ORIGINS,
        async_mode="gevent",          # gevent event loop
        ping_timeout=60,
        ping_interval=25,
    )

    # ---- Ensure collections + indexes ----
    with app.app_context():
        db = mongo.db
        for coll in ["users", "messages", "room_messages", "friends", "blocked"]:
            if coll not in db.list_collection_names():
                db.create_collection(coll)
                print(f"🆕 Created MongoDB collection: {coll}")

        db.users.create_index("email", unique=True)
        db.friends.create_index("user", unique=True)
        db.blocked.create_index("user", unique=True)
        db.messages.create_index([("sender", 1), ("receiver", 1), ("timestamp", 1)])
        db.room_messages.create_index([("room", 1), ("timestamp", 1)])
        print("✅ MongoDB collections & indexes verified")

    connected_users = {}  # lowercased username -> sid
    room_users = {}       # room -> set(usernames)
    online_status = {}    # lowercased username -> bool
    last_seen = {}        # lowercased username -> datetime

    # ---------------- Routes ----------------
    @app.route("/")
    def home():
        return "✅ ChatWave Backend Running (auto-friends + block + search)"

    @app.route("/healthz")
    def healthz():
        return jsonify({"ok": True}), 200

    @app.route("/register", methods=["POST", "OPTIONS"])
    def register_user():
        if request.method == "OPTIONS":
            return jsonify({"ok": True}), 200

        data = request.get_json() or {}
        username = data.get("username", "").strip()
        email = data.get("email", "").strip().lower()   # ✅ Normalize email
        password = data.get("password", "")

        if not username or not email or not password:
            return jsonify({"error": "Missing required fields"}), 400

        existing_user = mongo.db.users.find_one({"email": email})
        if existing_user:
            print(f"⚠️ Attempted re-register: {email}")
            return jsonify({"error": "User already exists"}), 409

        hashed_pw = generate_password_hash(password)
        mongo.db.users.insert_one({
            "username": username,
            "email": email,
            "password": hashed_pw,
            "created_at": datetime.now(timezone.utc)
        })

        print(f"✅ Registered new user: {username} ({email})")
        return jsonify({"message": "User registered successfully!"}), 201


    @app.route("/login", methods=["POST", "OPTIONS"])
    def login_user():
        if request.method == "OPTIONS":
            return jsonify({"ok": True}), 200

        data = request.get_json() or {}
        email = data.get("email", "").strip().lower()   # ✅ Normalize email
        password = data.get("password", "")

        user = mongo.db.users.find_one({"email": email})
        if not user:
            print(f"❌ Login failed: no user found for {email}")
            return jsonify({"error": "Invalid credentials"}), 401

        if not check_password_hash(user["password"], password):
            print(f"❌ Login failed: wrong password for {email}")
            return jsonify({"error": "Invalid credentials"}), 401

        token = create_access_token(identity=str(user["_id"]), expires_delta=timedelta(days=1))
        print(f"✅ {user['username']} logged in successfully ({email})")
        return jsonify({
            "message": "Login successful!",
            "token": token,
            "username": user["username"],
        }), 200


    # ============================================
# 🔐 PASSWORD RESET ROUTES (WORKING WITH BREVO)
# ============================================

    @app.route("/forgot-password", methods=["POST"])
    def forgot_password():
        data = request.get_json() or {}
        email = (data.get("email") or "").strip().lower()

        if not email:
            return jsonify({"error": "Email is required"}), 400

        # Check if user exists
        user = mongo.db.users.find_one({"email": email})
        if not user:
            print(f"❌ No user found for {email}")
            return jsonify({"error": "User not found"}), 404

        # Generate reset token (30 min expiry handled in reset endpoint)
        token = serializer.dumps(email, salt="password-reset-salt")

        # 🔗 Use your real frontend reset page:
        reset_link = f"https://chatwave-frontend-r4vwc5v1v-hanis-projects-d61265e6.vercel.app/reset-password/{token}"

        # 🧩 Initialize Brevo API client
        configuration = sib_api_v3_sdk.Configuration()
        configuration.api_key['api-key'] = app.config.get("BREVO_API_KEY")
        api_instance = sib_api_v3_sdk.TransactionalEmailsApi(sib_api_v3_sdk.ApiClient(configuration))

        # Compose transactional email
        email_obj = sib_api_v3_sdk.SendSmtpEmail(
            to=[{"email": email}],
            sender={"email": "varshinimanchikalapudi@10174898.brevosend.com", "name": "ChatWave"},
            subject="ChatWave Password Reset 🔐",
            html_content=f"""
                <div style='font-family:Inter,sans-serif;max-width:520px;margin:auto;border:1px solid #e2e8f0;padding:20px;border-radius:10px;background:#f8fafc;'>
                    <h2 style='color:#2563eb;text-align:center;margin-top:0;'>Password Reset Request</h2>
                    <p>Hello <b>{user.get('username', 'there')}</b>,</p>
                    <p>Click the button below to reset your ChatWave password:</p>
                    <p style='text-align:center;margin:22px 0;'>
                        <a href='{reset_link}' style='background:#2563eb;color:#fff;padding:12px 18px;border-radius:8px;text-decoration:none;font-weight:600;display:inline-block;'>
                            Reset Password
                        </a>
                    </p>
                    <p>If you didn’t request this, you can safely ignore this email.</p>
                    <p style='color:#64748b;font-size:13px;margin-bottom:0;'>This link expires in 30 minutes.</p>
                </div>
            """
        )

        try:
            api_instance.send_transac_email(email_obj)
            print(f"✅ Password reset email sent to {email}")
            return jsonify({"message": "Reset link sent successfully!"}), 200
        except ApiException as e:
            print("❌ Brevo API Error:", e)
            return jsonify({"error": f"Email sending failed: {e}"}), 500


    @app.route("/reset-password/<token>", methods=["POST"])
    def reset_password(token):
        try:
            # 30 minutes expiry
            email = serializer.loads(token, salt="password-reset-salt", max_age=1800)
        except SignatureExpired:
            return jsonify({"error": "Link expired"}), 400
        except BadSignature:
            return jsonify({"error": "Invalid or tampered link"}), 400

        data = request.get_json() or {}
        new_password = data.get("password")
        if not new_password:
            return jsonify({"error": "New password required"}), 400

        hashed_pw = generate_password_hash(new_password)
        mongo.db.users.update_one({"email": email}, {"$set": {"password": hashed_pw}})

        print(f"✅ Password successfully reset for {email}")
        return jsonify({"message": "Password updated successfully!"}), 200


    @app.route("/search_users", methods=["GET"])
    def search_users():
        q = request.args.get("q", "").strip()
        if not q:
            return jsonify([])
        cursor = mongo.db.users.find(
            {"username": {"$regex": q, "$options": "i"}},
            {"_id": 0, "username": 1}
        )
        return jsonify(list(cursor))

    @app.route("/status/<username>")
    def get_status(username):
        uname = username.lower()
        if online_status.get(uname):
            return jsonify({"status": "online"})
        if uname in last_seen:
            diff = datetime.now(timezone.utc) - last_seen[uname]
            mins = int(diff.total_seconds() // 60)
            return jsonify({"status": f"last seen {mins} min ago"})
        return jsonify({"status": "offline"})

    # ---------------- Socket.IO ----------------
    @socketio.on("connect")
    def handle_connect():
        print(f"🟢 Connected: {request.sid}")

    def _get_friends(username: str):
        doc = mongo.db.friends.find_one({"user": username})
        return doc.get("list", []) if doc else []

    def _get_blocked(username: str):
        doc = mongo.db.blocked.find_one({"user": username})
        return doc.get("list", []) if doc else []

    def _either_blocked(a: str, b: str) -> bool:
        return b in _get_blocked(a) or a in _get_blocked(b)

    def _emit_lists(username: str):
        friends_list = _get_friends(username)
        blocked_list = _get_blocked(username)
        sid = connected_users.get(username.lower())
        if sid:
            emit("lists", {"friends": friends_list, "blocked": blocked_list}, room=sid)
            emit("friend_list", friends_list, room=sid)
            emit("blocked_list", blocked_list, room=sid)

    @socketio.on("register_user")
    def handle_register_user(data):
        username = (data or {}).get("username")
        if not username:
            return
        uname = username.lower()
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
                "read": m.get("read", False),
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

        if _either_blocked(sender, receiver):
            emit(
                "receive_private_message",
                {
                    "system": True,
                    "message": "Message not delivered: communication is blocked",
                    "timestamp": timestamp.isoformat(),
                    "sender": sender,
                    "receiver": receiver,
                },
                room=request.sid,
            )
            return

        room_name = "_".join(sorted([sender, receiver]))
        join_room(room_name)

        result = mongo.db.messages.insert_one({
            "sender": sender,
            "receiver": receiver,
            "message": message,
            "timestamp": timestamp,
            "read": False,
        })
        msg_id = str(result.inserted_id)
        emit("receive_private_message", {
            "_id": msg_id,
            "sender": sender,
            "receiver": receiver,
            "message": message,
            "timestamp": timestamp.isoformat(),
        }, room=room_name)
        print(f"💬 {sender} → {receiver}: {message}")

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

    @socketio.on("block_user")
    def block_user_evt(data):
        blocker = (data or {}).get("blocker")
        blocked = (data or {}).get("blocked")
        if not blocker or not blocked:
            return
        mongo.db.blocked.update_one({"user": blocker}, {"$addToSet": {"list": blocked}}, upsert=True)
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

    @socketio.on("join_room")
    def handle_join_room(data):
        username = (data or {}).get("username")
        room = (data or {}).get("room")
        if not username or not room:
            return

        join_room(room)
        room_users.setdefault(room, set()).add(username)

        emit("receive_room_message", {
            "system": True,
            "room": room,
            "message": f"{username} joined the room",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }, room=room)

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
        result = mongo.db.room_messages.insert_one({
            "sender": sender,
            "room": room,
            "message": message,
            "timestamp": timestamp,
        })
        msg_id = str(result.inserted_id)
        emit("receive_room_message", {
            "_id": msg_id,
            "sender": sender,
            "message": message,
            "timestamp": timestamp.isoformat(),
            "room": room
        }, room=room)
        print(f"🏠 {sender}@{room}: {message}")

    @socketio.on("typing")
    def handle_typing(data):
        user = (data or {}).get("user")
        receiver = (data or {}).get("receiver")
        if user and receiver:
            emit("user_typing", {"user": user, "receiver": receiver}, broadcast=True)

    @socketio.on("disconnect")
    def handle_disconnect():
        disconnected = None
        for user, sid in list(connected_users.items()):
            if sid == request.sid:
                disconnected = user
                del connected_users[user]
                online_status[user] = False
                last_seen[user] = datetime.now(timezone.utc)
                break

        if disconnected:
            print(f"🔴 {disconnected} disconnected")
            for r, users in list(room_users.items()):
                if disconnected in users:
                    users.remove(disconnected)
                    emit("room_user_list", list(users), room=r)
                    emit("receive_room_message", {
                        "system": True,
                        "room": r,
                        "message": f"{disconnected} left the room",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }, room=r)

            emit("user_list", list(connected_users.keys()), broadcast=True)

    @socketio.on("mark_as_read")
    def mark_as_read(data):
        sender = (data or {}).get("sender")
        receiver = (data or {}).get("receiver")
        if not sender or not receiver:
            return

        mongo.db.messages.update_many(
            {"sender": sender, "receiver": receiver, "read": False},
            {"$set": {"read": True}},
        )

        sender_sid = connected_users.get(sender.lower())
        if sender_sid:
            emit("update_read_status", {"sender": sender, "receiver": receiver}, room=sender_sid)
        print(f"👁️ {receiver} has read messages from {sender}")

    @socketio.on("delete_message")
    def handle_delete_message(data):
        msg_id = data.get("msg_id")
        chat_type = data.get("type", "private")
        sender = data.get("sender")
        receiver = data.get("receiver")
        room = data.get("room")
        if not msg_id or not sender:
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
                else:
                    sid = connected_users.get(sender.lower())
                    if sid:
                        emit("message_deleted", {"msg_id": msg_id}, room=sid)

        elif chat_type == "room":
            result = mongo.db.room_messages.delete_one({"_id": obj_id})
            if result.deleted_count:
                emit("message_deleted", {"msg_id": msg_id, "room": room}, room=room)

    @socketio.on("delete_chat")
    def handle_delete_chat(data):
        user1 = (data or {}).get("user1", "").strip()
        user2 = (data or {}).get("user2", "").strip()
        if not user1 or not user2:
            return

        delete_query = {
            "$or": [
                {"sender": {"$regex": f"^{user1}$", "$options": "i"},
                 "receiver": {"$regex": f"^{user2}$", "$options": "i"}},
                {"sender": {"$regex": f"^{user2}$", "$options": "i"},
                 "receiver": {"$regex": f"^{user1}$", "$options": "i"}},
            ]
        }

        existing = list(mongo.db.messages.find(delete_query))
        print(f"🔍 Found {len(existing)} messages before deletion.")

        result = mongo.db.messages.delete_many(delete_query)
        print(f"🧹 Deleted {result.deleted_count} messages between {user1} and {user2}")

        mongo.db.friends.update_one({"user": user1}, {"$pull": {"list": user2}}, upsert=True)
        mongo.db.friends.update_one({"user": user2}, {"$pull": {"list": user1}}, upsert=True)

        room_name = "_".join(sorted([user1.lower(), user2.lower()]))
        emit("chat_deleted", {"user1": user1, "user2": user2}, room=room_name)
        _emit_lists(user1)
        _emit_lists(user2)

    return app, socketio


# -------------- Main (dev) --------------
if __name__ == "__main__":
    app, socketio = create_app()
    print("🚀 Starting ChatWave Backend (gevent)…")
    socketio.run(app, host="0.0.0.0", port=5000)
