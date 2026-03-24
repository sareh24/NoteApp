from datetime import timedelta

SECRET_KEY = "This is a place holder secret key. I will use a secret key in production."
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30  # Token valid for 30 mins

# Development bootstrap admin account for quick testing.
DEFAULT_ADMIN_EMAIL = "admin@noteapp.com"
DEFAULT_ADMIN_PASSWORD = "Admin123!"
DEFAULT_ADMIN_FIRST_NAME = "System"
DEFAULT_ADMIN_LAST_NAME = "Admin"