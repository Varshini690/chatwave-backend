import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    # Security keys
    SECRET_KEY = os.getenv("SECRET_KEY")
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")

    # MongoDB connection
    MONGO_URI = os.getenv("MONGO_URI")

    # Mail configuration (reads values from .env)
    MAIL_SERVER = os.getenv("MAIL_SERVER", "smtp.gmail.com")
    MAIL_PORT = int(os.getenv("MAIL_PORT", 587))
    MAIL_USE_TLS = os.getenv("MAIL_USE_TLS", "True").lower() in ["true", "1", "t"]
    MAIL_USERNAME = os.getenv("MAIL_USERNAME")       # will read your Gmail from .env
    MAIL_PASSWORD = os.getenv("MAIL_PASSWORD")       # will read your App Password from .env
    MAIL_DEFAULT_SENDER = (
        os.getenv("MAIL_DEFAULT_SENDER_NAME", "ChatWave"),
        os.getenv("MAIL_DEFAULT_SENDER", os.getenv("MAIL_USERNAME")),
    )
