import os

# Lets tests import the app without a real .env or database
os.environ.setdefault("DATABASE_URL", "sqlite://")
