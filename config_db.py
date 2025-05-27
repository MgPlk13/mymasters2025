import os
SECRET_KEY = os.environ.get("SECRET_KEY", "super_secret_key_123")

POSTGRES = {
    "user": "zazrab",
    "password": "12345",
    "host": "localhost",
    "port": 5432,
    "database": "analytics_db"
}

DATABASE_URI = (
    f"postgresql+psycopg2://{POSTGRES['user']}:{POSTGRES['password']}"
    f"@{POSTGRES['host']}:{POSTGRES['port']}/{POSTGRES['database']}"
)
