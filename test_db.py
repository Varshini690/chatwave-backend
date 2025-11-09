from pymongo import MongoClient

uri = "mongodb+srv://ChatWave:Varshu23@chatwave.4cgzbuc.mongodb.net/chatwave?retryWrites=true&w=majority&appName=ChatWave"

client = MongoClient(uri)
try:
    client.admin.command('ping')
    print("✅ MongoDB connection successful!")
except Exception as e:
    print("❌ MongoDB connection failed:", e)
