import os
import random
import string
import shutil
import zipfile
import io
from captcha.image import ImageCaptcha  # Import the new library
from config import UPLOAD_ROOT,SMTP_SERVER,SMTP_PORT,SMTP_USER,SMTP_PASS

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

def generate_captcha():
    # Configure the ImageCaptcha instance
    # You can change width/height/fonts here
    image = ImageCaptcha(width=120, height=40, font_sizes=(25, 35, 40))
    
    # Generate random text (4 chars)
    captcha_text = ''.join(random.choices(string.ascii_uppercase + string.digits, k=4))
    
    # Generate the image
    # image.generate() returns a BytesIO object
    data = image.generate(captcha_text)
    
    # Return text and raw byte data
    return captcha_text, data.getvalue()

def generate_random_password(length=12):
    """Generates a secure random password."""
    # Ensure at least one of each type
    chars = string.ascii_letters + string.digits + "!@#$%"
    password = [
        random.choice(string.ascii_uppercase),
        random.choice(string.ascii_lowercase),
        random.choice(string.digits),
        random.choice("!@#$%")
    ]
    # Fill the rest
    password += [random.choice(chars) for _ in range(length - 4)]
    random.shuffle(password)
    return ''.join(password)

def get_user_dir(user_id):
    path = os.path.join(UPLOAD_ROOT, str(user_id))
    if not os.path.exists(path):
        os.makedirs(path)
    return path

def is_safe_path(base, path):
    # Prevent Directory Traversal
    return os.path.abspath(path).startswith(os.path.abspath(base))

def zip_target(path, root_path):
    # Zips a file or folder
    mem_file = io.BytesIO()
    with zipfile.ZipFile(mem_file, 'w', zipfile.ZIP_DEFLATED) as zf:
        if os.path.isdir(path):
            for root, dirs, files in os.walk(path):
                for file in files:
                    abs_file = os.path.join(root, file)
                    rel_file = os.path.relpath(abs_file, os.path.dirname(path))
                    zf.write(abs_file, rel_file)
        else:
            zf.write(path, os.path.basename(path))
    mem_file.seek(0)
    return mem_file

def send_mail(email,subject,html_content):
    try:
        msg = MIMEMultipart("alternative")
        msg['Subject'] = subject
        msg['From'] = SMTP_USER
        msg['To'] = email
        msg.attach(MIMEText(html_content, "html"))

        # Connect to SMTP Server
        s = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        #s.starttls()
        s.login(SMTP_USER, SMTP_PASS)
        s.send_message(msg)
        s.quit()
        
        print(f"[SMTP] Email sent to {email}")
        return True, None
        
    except Exception as e:
        print(f"[SMTP Error] Could not send email: {e}")
        return False, 'Send email error.'

def get_directory_size(path):
    """Returns total size of a directory in bytes."""
    total_size = 0
    for dirpath, dirnames, filenames in os.walk(path):
        for f in filenames:
            fp = os.path.join(dirpath, f)
            # skip if it is symbolic link
            if not os.path.islink(fp):
                total_size += os.path.getsize(fp)
    return total_size

def format_size(size):
    """Helper to format bytes to KB/MB/GB"""
    power = 2**10
    n = 0
    power_labels = {0 : '', 1: 'K', 2: 'M', 3: 'G', 4: 'T'}
    while size > power:
        size /= power
        n += 1
    return f"{size:.2f} {power_labels[n]}B"