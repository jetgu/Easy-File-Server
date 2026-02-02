import os

# Server Settings
PORT = 8888
HTTPS_PORT = 8443
HTTPS_REDIRECT  = False
SSL_ENABLED = True # Set to True if you have .crt and .key files
SSL_CERT = "ServerCert.pem"
SSL_KEY = "ServerKey.pem"
COOKIE_SECRET = "CHANGE_THIS_TO_A_LONG_RANDOM_STRING_FOR_SECURITY"
SESSION_TIMEOUT_MINUTES = 30  # User will be logged out after 30 mins of inactivity

# Paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_ROOT = os.path.join(BASE_DIR, "static", "uploads")
DB_PATH = os.path.join(BASE_DIR, "file_server.db")

# SMTP Settings (For Forgot Password)
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USER = "your_email@gmail.com"
SMTP_PASS = "your_app_password"

# Logging Settings
LOG_FOLDER = os.path.join(BASE_DIR, "logs")
LOG_FILE = os.path.join(LOG_FOLDER, "server.log")
LOG_MAX_BYTES = 10 * 1024 * 1024  # 10 MB
LOG_BACKUP_COUNT = 5              # Keep last 5 log files

if not os.path.exists(UPLOAD_ROOT):
    os.makedirs(UPLOAD_ROOT)

if not os.path.exists(LOG_FOLDER):
    os.makedirs(LOG_FOLDER)