# from pymongo import MongoClient

# uri = "mongodb+srv://ChatWave:Varshu23@chatwave.4cgzbuc.mongodb.net/chatwave?retryWrites=true&w=majority&appName=ChatWave"

# client = MongoClient(uri)
# try:
#     client.admin.command('ping')
#     print("✅ MongoDB connection successful!")
# except Exception as e:
#     print("❌ MongoDB connection failed:", e)
from flask_mail import Mail, Message
from app import create_app

app, _ = create_app()
mail = Mail(app)

with app.app_context():
    msg = Message(
        subject="ChatWave Brevo SMTP Test ✅",
        sender=app.config['MAIL_DEFAULT_SENDER'],
        recipients=["varshinimanchikalapudi@gmail.com"],
        body="Hi Varshini! This is a test email from ChatWave using Brevo SMTP."
    )
    mail.send(msg)
    print("✅ Test email sent successfully!")
