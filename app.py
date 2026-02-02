import tornado.ioloop
import tornado.web
import tornado.httpserver
import tornado.gen
import os
import bcrypt
import json
import smtplib
import shutil
import zipfile
import secrets
import time
import sqlite3 
import logging
import io
import sys
from logging.handlers import RotatingFileHandler
from email.mime.text import MIMEText
from datetime import datetime, timedelta 
from config import *
from database import init_db, get_db
from utils import generate_captcha, get_user_dir, is_safe_path, zip_target, generate_random_password, send_mail, get_directory_size, format_size

class BaseHandler(tornado.web.RequestHandler):
    def prepare(self):
        if HTTPS_REDIRECT and self.request.protocol == "http":
            # Build full HTTPS URL with explicit port
            host = self.request.host.split(':')[0]  # remove any accidental port from Host header
            https_url = f"https://{host}:{HTTPS_PORT}{self.request.uri}"
            self.redirect(https_url, permanent=True)  # 301 Permanent Redirect

    def get_current_user(self):
        # 1. Get the raw cookie
        user_id = self.get_secure_cookie("user_id")
        
        # 2. If no cookie, return None
        if not user_id: 
            return None
        
        # 3. Refresh the Session (Sliding Expiration)
        # This extends the cookie life by another 30 minutes every time the user clicks something.
        try:
            # We must decode bytes to string for set_secure_cookie depending on tornado version, 
            # but usually passing bytes is fine. To be safe, we keep it as is.
            expires = datetime.now() + timedelta(minutes=SESSION_TIMEOUT_MINUTES)
            self.set_secure_cookie("user_id", user_id, expires=expires)
        except Exception as e:
            logging.info(f"Session refresh error: {e}")

        # 4. Fetch user from DB
        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE id = ?", (int(user_id),)).fetchone()
        conn.close()
        return user

    def get_settings(self):
        conn = get_db()
        rows = conn.execute("SELECT * FROM settings").fetchall()
        conn.close()
        return {r['key']: r['value'] for r in rows}

    def get_target_context(self):
        """
        Returns (target_user_dict, absolute_root_path, target_user_id_param)
        If admin passes 'target_user_id', we return that user's info.
        Otherwise, we return the current logged-in user's info.
        """
        current = self.current_user
        target_id_param = self.get_argument("target_user_id", "")
        
        # Only Admin can switch users
        if current['is_admin'] and target_id_param:
            try:
                t_id = int(target_id_param)
                conn = get_db()
                target = conn.execute("SELECT * FROM users WHERE id=?", (t_id,)).fetchone()
                conn.close()
                if target:
                    return target, get_user_dir(t_id), str(t_id)
            except ValueError:
                pass
        
        # Default: Return current user
        return current, get_user_dir(current['id']), ""

class AuthHandler(BaseHandler):
    def get(self, action):
        # Clean the action string (remove trailing slash or params if any)
        action = action.rstrip("/")
        
        # Captcha Handling
        if action.startswith("captcha"):
            text, img_data = generate_captcha()
            self.set_secure_cookie("captcha", text)
            self.set_header("Content-Type", "image/png")
            self.write(img_data)
            return

        # Logout Handling
        if action == "logout":
            self.clear_cookie("user_id")
            self.redirect("/login")
            return

        # Render Login/Register/Forgot pages
        # Ensure the template exists to prevent errors
        if action in ["login", "register", "forgot"]:
            self.render(f"{action}.html", error=None, success=None)
        else:
            self.send_error(404)

    async def post(self, action):
        action = action.rstrip("/")
        
        email = self.get_argument("email", "")
        password = self.get_argument("password", "")
        captcha_input = self.get_argument("captcha", "")
        
        conn = get_db()
        
        # LOGIC FOR REGISTER
        if action == "register":
            # Verify Captcha
            real_captcha = self.get_secure_cookie("captcha")
            if not real_captcha or captcha_input.upper() != real_captcha.decode().upper():
                self.render("register.html", error="Invalid Captcha")
                conn.close()
                return

            # --- NEW: Get extra fields ---
            info = self.get_argument("info", "")
            confirm_password = self.get_argument("confirm_password", "")

            # --- NEW: Validation ---
            if len(password) <= 8:
                self.render("register.html", error="Password must be longer than 8 characters.")
                conn.close()
                return
            
            if password != confirm_password:
                self.render("register.html", error="Passwords do not match.")
                conn.close()
                return

            hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            try:
                conn.execute("INSERT INTO users (email, password, created_at, is_active, info) VALUES (?, ?, ?, ?, ?)",
                             (email, hashed, datetime.now().timestamp(), 1, info))
                conn.commit()
                self.redirect("/login")
            except sqlite3.IntegrityError:
                self.render("register.html", error="Email already exists")
        
        # LOGIC FOR LOGIN
        elif action == "login":
            # Verify Captcha
            real_captcha = self.get_secure_cookie("captcha")
            if not real_captcha or captcha_input.upper() != real_captcha.decode().upper():
                self.render("login.html", error="Invalid Captcha")
                conn.close()
                return

            user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
            if user and bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
                # --- NEW: Check if Active ---
                if user['is_active'] == 0:
                    self.render("login.html", error="Account is disabled. Contact Admin.")
                    conn.close()
                    return
                # ----------------------------

                #self.set_secure_cookie("user_id", str(user['id']))
                # Set cookie with explicit expiration time
                expires = datetime.now() + timedelta(minutes=SESSION_TIMEOUT_MINUTES)
                self.set_secure_cookie("user_id", str(user['id']), expires=expires)
                self.redirect("/")
            else:
                self.render("login.html", error="Invalid credentials")
        
        # LOGIC FOR FORGOT PASSWORD
        elif action == "forgot":
            # Verify Captcha
            real_captcha = self.get_secure_cookie("captcha")
            if not real_captcha or captcha_input.upper() != real_captcha.decode().upper():
                self.render("forgot.html", error="Invalid Captcha", success=None)
                conn.close()
                return

            user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
            if user:
                new_pass = generate_random_password(12)
                hashed = bcrypt.hashpw(new_pass.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
                conn.execute("UPDATE users SET password = ? WHERE id = ?", (hashed, user['id']))
                conn.commit()

                subject = "Password Reset Request - EasyFile Server"
                html_content = f"""
                <html>
                <body style="font-family: sans-serif; color: #333;">
                    <h3>Password Reset</h3>
                    <p>Your new temporary password is:</p>
                    <div style="background: #eee; padding: 10px; font-family: monospace; font-size: 1.2em;">
                        {new_pass}
                    </div>
                    <p>Please change it immediately.</p>
                </body>
                </html>
                """
                
                logging.info(f"Password reset for {email} to {new_pass}")
                # Send Email in Background Thread
                success_status, error_msg = await tornado.ioloop.IOLoop.current().run_in_executor(
                    None,             # Use default thread pool
                    send_mail,  # Function to call
                    email,            # Arg 1
                    subject,          # Arg 2
                    html_content      # Arg 3
                )
                
                if success_status:
                    self.render("forgot.html", error=None, success="A new password has been sent to your email.")
                else:
                    # If email fails, print to console so you can still login
                    logging.info(f"--- MOCK (Email Failed) ---\nUser: {email}\nPass: {new_pass}\n-----------------------")
                    self.render("forgot.html", error=f"Email failed. Error: {error_msg}", success=None)
                
            else:
                self.render("login.html", error="account error")
        
        conn.close()

class DashboardHandler(BaseHandler):
    #@tornado.web.authenticated
    def get(self):
        # 1. GUEST CHECK: If not logged in, show Landing Page
        if not self.current_user:
            self.render("index.html")
            return

        target_user, user_root, target_id_param = self.get_target_context()
        #user_root = get_user_dir(self.current_user['id'])
        rel_path = self.get_argument("path", "")
        current_path = os.path.join(user_root, rel_path.strip("/"))
        
        if not is_safe_path(user_root, current_path):
            self.redirect("/")
            return

        # --- NEW: QUOTA CALCULATION ---
        # 1. Get Quota from DB (in MB) -> convert to Bytes
        quota_mb = target_user['quota'] if target_user['quota'] else 5120
        quota_bytes = quota_mb * 1024 * 1024
        
        # 2. Calculate Used Space
        used_bytes = get_directory_size(user_root)
        
        # 3. Calculate Percent
        usage_percent = min(100, int((used_bytes / quota_bytes) * 100)) if quota_bytes > 0 else 0
        
        # 4. Format for Display
        usage_str = f"{format_size(used_bytes)} / {format_size(quota_bytes)}"
        # ------------------------------

        items = []
        try:
            with os.scandir(current_path) as it:
                for entry in it:
                    stats = entry.stat()
                    if entry.is_dir():
                        ftype = "Folder"
                    else:
                        # Get extension, remove dot, uppercase (e.g., .txt -> TXT)
                        ext = os.path.splitext(entry.name)[1].lstrip('.').upper()
                        ftype = ext if ext else "File"

                    raw_path = os.path.join(rel_path, entry.name)
                    web_safe_path = raw_path.replace("\\", "/").strip("/")

                    items.append({
                        "name": entry.name,
                        "is_dir": entry.is_dir(),
                        "size": stats.st_size,
                        "mtime": datetime.fromtimestamp(stats.st_mtime).strftime('%Y-%m-%d %H:%M'),
                        "path": web_safe_path,
                        "type": ftype
                    })
        except FileNotFoundError:
            self.redirect("/")
            return

        # --- SORTING LOGIC ---
        sort_by = self.get_argument("sort", "name")
        order = self.get_argument("order", "asc") # Default to ascending
        
        # Sort logic
        reverse_sort = (order == 'desc')
        items.sort(key=lambda x: x[sort_by] if sort_by in x else x['name'], reverse=reverse_sort)
        
        view_style = self.get_argument("view", "list")
        
        # --- FIX: PASS 'sort' AND 'order' HERE ---
        self.render("dashboard.html", 
                    items=items, 
                    current_path=rel_path, 
                    view=view_style, 
                    sort=sort_by,   # <--- This was missing
                    order=order,    # <--- This was missing
                    user=self.current_user,
                    # Pass target info to template so we can persist it in links
                    target_user=target_user, 
                    target_user_id=target_id_param,
                    usage_percent=usage_percent,
                    usage_str=usage_str)


class FileActionHandler(BaseHandler):
    @tornado.web.authenticated
    async def post(self):
        target_user, user_root, target_id_param = self.get_target_context()
        action = self.get_argument("action")
        #user_root = get_user_dir(self.current_user['id'])
        rel_path = self.get_argument("current_path", "")
        current_abs = os.path.join(user_root, rel_path.strip("/"))
        
        if not is_safe_path(user_root, current_abs):
            self.finish({"status": "error", "msg": "Invalid path"})
            return

        logging.info(f"action: {action}")
        if action == "mkdir":
            new_folder = self.get_argument("name")
            os.makedirs(os.path.join(current_abs, new_folder), exist_ok=True)
            
        elif action == "delete":
            target = self.get_argument("target")
            target_path = os.path.join(current_abs, target)
            if is_safe_path(user_root, target_path):
                if os.path.isdir(target_path): shutil.rmtree(target_path)
                else: os.remove(target_path)
                
        elif action == "upload":
            settings = self.get_settings()
            max_mb = int(settings.get('max_upload_size', 50))

            # --- NEW: QUOTA CHECK ---
            # 1. Get User Quota
            if target_user:
                # If admin is uploading to another user, use that user's quota
                quota_mb = target_user['quota'] 
                current_uid = target_user['id']
                current_root = user_root
            else:
                # Normal user
                quota_mb = self.current_user['quota']
                current_uid = self.current_user['id']
                current_root = get_user_dir(current_uid)
                
            quota_bytes = (quota_mb if quota_mb else 5120) * 1024 * 1024
            used_bytes = get_directory_size(current_root)
            remaining_bytes = quota_bytes - used_bytes
            # ------------------------
            
            if self.request.files:
                for field_name, files in self.request.files.items():
                    for info in files:
                        file_size = len(info['body'])
                        if file_size > max_mb * 1024 * 1024:
                            self.finish({"status": "error", "msg": "File too large"})
                            return

                        # --- NEW: Check Quota ---
                        if file_size > remaining_bytes:
                            self.finish({"status": "error", "msg": "Disk Quota Exceeded."})
                            return
                        # ------------------------

                        filename = info['filename']
                        with open(os.path.join(current_abs, filename), 'wb') as f:
                            f.write(info['body'])
                        
        elif action == "edit_save":
            filename = self.get_argument("filename")
            content = self.get_argument("content")
            file_path = os.path.join(current_abs, filename)
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)

        elif action == "unzip":
            target = self.get_argument("target")
            target_path = os.path.join(current_abs, target)
            if zipfile.is_zipfile(target_path):
                with zipfile.ZipFile(target_path, 'r') as zip_ref:
                    zip_ref.extractall(current_abs)

        # --- NEW: Share Action ---
        elif action == "share":
            target = self.get_argument("target") # Filename
            days = int(self.get_argument("days", 1))
            
            # Create unique token
            token = secrets.token_urlsafe(16)
            file_rel_path = os.path.join(rel_path, target).strip("/")
            
            # Calculate expiry
            now = time.time()
            expires_at = now + (days * 24 * 60 * 60)
            
            user_id = self.current_user['id']
            if target_id_param:
               user_id = target_id_param

            conn = get_db()
            conn.execute("INSERT INTO shares (token, user_id, file_path, created_at, expires_at) VALUES (?, ?, ?, ?, ?)",
                         (token, user_id, file_rel_path, now, expires_at))
            conn.commit()
            conn.close()
            
            # Return JSON response for the AJAX call
            share_url = f"{self.request.protocol}://{self.request.host}/share/{token}"
            self.finish({"status": "success", "link": share_url})
            return
        # -------------------------
        # --- NEW: PASTE ACTION (Handle Copy/Cut) ---
        elif action == "paste":
            source_rel = self.get_argument("source_path")
            mode = self.get_argument("mode") # 'copy' or 'cut'
            
            source_abs = os.path.join(user_root, source_rel.strip("/"))
            
            # Security Checks
            if not is_safe_path(user_root, source_abs) or not os.path.exists(source_abs):
                self.finish({"status": "error", "msg": "Source file not found"})
                return

            filename = os.path.basename(source_abs)
            dest_abs = os.path.join(current_abs, filename)

            # Prevent pasting into itself (for folders)
            if os.path.isdir(source_abs) and dest_abs.startswith(source_abs):
                self.finish({"status": "error", "msg": "Cannot paste folder into itself"})
                return

            # Handle Name Conflict (Rename if exists: file.txt -> file_copy.txt)
            if os.path.exists(dest_abs):
                base, ext = os.path.splitext(filename)
                timestamp = int(time.time())
                dest_abs = os.path.join(current_abs, f"{base}_{timestamp}{ext}")

            try:
                if mode == 'cut':
                    # Move
                    shutil.move(source_abs, dest_abs)
                
                elif mode == 'copy':
                    # Check Quota before Copying
                    if target_user: # Admin acting on user
                        quota_mb = target_user['quota']
                        current_uid = target_user['id']
                        quota_root = user_root
                    else: # User acting on self
                        quota_mb = self.current_user['quota']
                        current_uid = self.current_user['id']
                        quota_root = get_user_dir(current_uid)

                    quota_bytes = (quota_mb if quota_mb else 5120) * 1024 * 1024
                    used_bytes = get_directory_size(quota_root)
                    
                    # Calculate Source Size
                    if os.path.isdir(source_abs):
                        src_size = get_directory_size(source_abs)
                    else:
                        src_size = os.path.getsize(source_abs)
                        
                    if used_bytes + src_size > quota_bytes:
                         self.finish({"status": "error", "msg": "Disk Quota Exceeded during copy."})
                         return

                    # Perform Copy
                    if os.path.isdir(source_abs):
                        shutil.copytree(source_abs, dest_abs)
                    else:
                        shutil.copy2(source_abs, dest_abs)

                self.finish({"status": "success"})
            except Exception as e:
                logging.error(f"Paste Error: {e}")
                self.finish({"status": "error", "msg": str(e)})
            return
        # -------------------------------------------
        # --- NEW: RENAME ACTION ---
        elif action == "rename":
            old_name = self.get_argument("old_name")
            new_name = self.get_argument("new_name")
            
            # Construct absolute paths
            old_abs = os.path.join(current_abs, old_name)
            new_abs = os.path.join(current_abs, new_name)
            
            # 1. Security Checks
            if not is_safe_path(user_root, old_abs) or not is_safe_path(user_root, new_abs):
                self.finish({"status": "error", "msg": "Invalid path"})
                return

            # 2. Validation
            if not os.path.exists(old_abs):
                self.finish({"status": "error", "msg": "File not found"})
                return

            if os.path.exists(new_abs):
                self.finish({"status": "error", "msg": "Name already exists"})
                return
            
            # 3. Rename
            try:
                os.rename(old_abs, new_abs)
                logging.info(f"User {self.current_user['email']} renamed '{old_name}' to '{new_name}'")
            except Exception as e:
                logging.error(f"Rename Error: {e}")
                self.finish({"status": "error", "msg": str(e)})
                return
        # --------------------------
        # --- NEW: CREATE FILE ACTION ---
        elif action == "mkfile":
            filename = self.get_argument("name")
            
            # Construct absolute path
            target_path = os.path.join(current_abs, filename)
            
            # 1. Security Check
            if not is_safe_path(user_root, target_path):
                self.finish({"status": "error", "msg": "Invalid path"})
                return
            
            # 2. Check if exists
            if os.path.exists(target_path):
                self.finish({"status": "error", "msg": "File already exists"})
                return

            # 3. Create Empty File
            try:
                # 'w' mode creates a new empty file
                with open(target_path, 'w') as f:
                    pass 
                logging.info(f"User {self.current_user['email']} created file: {filename}")
            except Exception as e:
                logging.error(f"Mkfile Error: {e}")
                self.finish({"status": "error", "msg": str(e)})
                return
        # -------------------------------

        # Redirect needs to persist the target_user_id
        redirect_url = f"/?path={rel_path}"
        if target_id_param:
            redirect_url += f"&target_user_id={target_id_param}"
        self.redirect(redirect_url)


class DownloadHandler(BaseHandler):
    @tornado.web.authenticated
    async def get(self):
        target_user, user_root, target_id_param = self.get_target_context()
        #user_root = get_user_dir(self.current_user['id'])
        rel_path = self.get_argument("path", "")
        file_path = os.path.join(user_root, rel_path.strip("/"))
        action = self.get_argument("action", "download")

        if not is_safe_path(user_root, file_path) or not os.path.exists(file_path):
            raise tornado.web.HTTPError(404)

        # Speed limit logic
        settings = self.get_settings()
        speed_limit_kb = int(settings.get('download_speed_limit', 0))
        chunk_size = 64 * 1024 # 64KB chunks

        if action == "zip":
            mem_zip = zip_target(file_path, user_root)
            self.set_header('Content-Type', 'application/zip')
            self.set_header('Content-Disposition', f'attachment; filename="{os.path.basename(file_path)}.zip"')
            self.write(mem_zip.getvalue())
            return
        
        elif action == "edit_load":
             try:
                 with open(file_path, 'r', encoding='utf-8') as f:
                     self.write(f.read())
             except:
                 self.write("Cannot read binary file.")
             return

        self.set_header('Content-Type', 'application/octet-stream')
        self.set_header('Content-Disposition', f'attachment; filename="{os.path.basename(file_path)}"')
        
        with open(file_path, 'rb') as f:
            while True:
                data = f.read(chunk_size)
                if not data: break
                self.write(data)
                await self.flush()
                if speed_limit_kb > 0:
                    sleep_time = len(data) / (speed_limit_kb * 1024)
                    await tornado.gen.sleep(sleep_time)

class AdminHandler(BaseHandler):
    @tornado.web.authenticated
    def get(self):
        if not self.current_user['is_admin']:
            self.redirect("/")
            return
        conn = get_db()
        users = conn.execute("SELECT * FROM users").fetchall()
        settings_rows = conn.execute("SELECT * FROM settings").fetchall()
        conn.close()
        settings = {r['key']: r['value'] for r in settings_rows}
        self.render("admin.html", users=users, settings=settings)

    @tornado.web.authenticated
    def post(self):
        if not self.current_user['is_admin']: return
        
        action = self.get_argument("action")
        conn = get_db()
        
        if action == "update_settings":
            max_size = self.get_argument("max_upload_size")
            speed = self.get_argument("download_speed_limit")
            conn.execute("UPDATE settings SET value=? WHERE key='max_upload_size'", (max_size,))
            conn.execute("UPDATE settings SET value=? WHERE key='download_speed_limit'", (speed,))
        # --- NEW: Toggle User Status ---
        elif action == "toggle_status":
            user_id = self.get_argument("user_id")
            current_status = int(self.get_argument("current_status"))
            new_status = 0 if current_status == 1 else 1
            # Prevent disabling self
            if int(user_id) != self.current_user['id']:
                conn.execute("UPDATE users SET is_active=? WHERE id=?", (new_status, user_id))
        # -------------------------------
        # --- NEW: Update User Quota ---
        elif action == "update_quota":
            user_id = self.get_argument("user_id")
            new_quota = self.get_argument("quota_mb")
            conn.execute("UPDATE users SET quota=? WHERE id=?", (new_quota, user_id))
        # ------------------------------

        conn.commit()
        conn.close()
        self.redirect("/admin")

class ShareHandler(BaseHandler):
    # Note: No @tornado.web.authenticated here, links are public!
    async def get(self, token):
        conn = get_db()
        share = conn.execute("SELECT * FROM shares WHERE token = ?", (token,)).fetchone()
        conn.close()
        
        # 1. Check if link exists
        if not share:
            self.write("Invalid or expired link.")
            return

        # 2. Check if expired
        if time.time() > share['expires_at']:
            self.write("This link has expired.")
            return
            
        # 3. Locate file
        user_root = get_user_dir(share['user_id'])
        file_path = os.path.join(user_root, share['file_path'])
        
        if not os.path.exists(file_path):
            self.write("The shared file has been deleted by the owner.")
            return

        # 4. Serve File (Copying logic from DownloadHandler)
        # Speed limit logic
        settings = self.get_settings()
        speed_limit_kb = int(settings.get('download_speed_limit', 0))
        chunk_size = 64 * 1024
        self.set_header('Content-Type', 'application/octet-stream')
        self.set_header('Content-Disposition', f'attachment; filename="{os.path.basename(file_path)}"')
        
        with open(file_path, 'rb') as f:
            while True:
                data = f.read(chunk_size)
                if not data: break
                self.write(data)
                await self.flush()
                if speed_limit_kb > 0:
                    sleep_time = len(data) / (speed_limit_kb * 1024)
                    await tornado.gen.sleep(sleep_time)

class UserSettingsHandler(BaseHandler):
    @tornado.web.authenticated
    def get(self):
        # Render the settings page with current user info
        self.render("settings.html", user=self.current_user, error=None, success=None)

    @tornado.web.authenticated
    def post(self):
        action = self.get_argument("action")
        conn = get_db()
        
        if action == "update_info":
            new_info = self.get_argument("info", "")
            conn.execute("UPDATE users SET info = ? WHERE id = ?", (new_info, self.current_user['id']))
            conn.commit()
            conn.close()
            self.render("settings.html", user=self.current_user, error=None, success="Profile info updated.")
            
        elif action == "change_password":
            old_pass = self.get_argument("old_password")
            new_pass = self.get_argument("new_password")
            confirm_pass = self.get_argument("confirm_password")
            
            # 1. Verify Old Password
            # Fetch fresh user data to get the hash
            db_user = conn.execute("SELECT * FROM users WHERE id=?", (self.current_user['id'],)).fetchone()
            
            if not bcrypt.checkpw(old_pass.encode('utf-8'), db_user['password'].encode('utf-8')):
                conn.close()
                self.render("settings.html", user=self.current_user, error="Incorrect old password", success=None)
                return

            # 2. Validate New Password
            if len(new_pass) <= 8:
                conn.close()
                self.render("settings.html", user=self.current_user, error="New password must be > 8 chars", success=None)
                return
                
            if new_pass != confirm_pass:
                conn.close()
                self.render("settings.html", user=self.current_user, error="New passwords do not match", success=None)
                return
            
            # 3. Save
            hashed = bcrypt.hashpw(new_pass.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            conn.execute("UPDATE users SET password = ? WHERE id = ?", (hashed, self.current_user['id']))
            conn.commit()
            conn.close()
            self.render("settings.html", user=self.current_user, error=None, success="Password changed successfully.")

class SourceCodeHandler(BaseHandler):
    async def get(self):
        file_path = os.path.join(BASE_DIR, "EasyFileServer_Source.zip")
        if not os.path.exists(file_path):
            self.write("File not found.")
            return

        chunk_size = 64 * 1024
        self.set_header('Content-Type', 'application/zip')
        self.set_header('Content-Disposition', 'attachment; filename="EasyFileServer_Source.zip"')
        with open(file_path, 'rb') as f:
            while True:
                data = f.read(chunk_size)
                if not data: break
                self.write(data)
                await self.flush()

class StaticRootFileHandler(tornado.web.RequestHandler):
    """
    Serves specific static files from the root directory (like ads.txt, robots.txt).
    """
    def get(self, filename):
        # Only allow specific safe files
        allowed_files = ["ads.txt", "robots.txt", "sitemap.xml"]
        
        if filename not in allowed_files:
            raise tornado.web.HTTPError(404)
            
        file_path = os.path.join(BASE_DIR, filename)
        
        if not os.path.exists(file_path):
            raise tornado.web.HTTPError(404)
            
        # Set content type based on extension
        if filename.endswith(".txt"):
            self.set_header("Content-Type", "text/plain")
        elif filename.endswith(".xml"):
            self.set_header("Content-Type", "application/xml")
            
        with open(file_path, 'rb') as f:
            self.write(f.read())

class ProtectedMediaHandler(tornado.web.StaticFileHandler):
    def get_current_user(self):
        user_id = self.get_secure_cookie("user_id")
        if not user_id: return None
        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE id = ?", (int(user_id),)).fetchone()
        conn.close()
        return user

    def validate_absolute_path(self, root, absolute_path):
        # DEBUG LOGGING
        logging.info(f"[Media Debug] Request Path: {absolute_path}")
        
        # 1. Check Login
        user = self.current_user
        if not user:
            logging.warning("[Media Debug] User not logged in")
            raise tornado.web.HTTPError(403, "Not logged in")

        # 2. Validate Path Security
        root = os.path.abspath(root)
        absolute_path = os.path.abspath(absolute_path)
        
        if not absolute_path.startswith(root):
            logging.warning(f"[Media Debug] Path traversal attempt: {absolute_path} is not in {root}")
            raise tornado.web.HTTPError(403, "Invalid path")

        # 3. Check Existence Manually (to catch 404s early)
        if not os.path.exists(absolute_path):
            logging.error(f"[Media Debug] FILE NOT FOUND ON DISK: {absolute_path}")
            # This is likely the cause of your 404
            raise tornado.web.HTTPError(404)

        # 4. Check Ownership
        try:
            # Rel path: e.g., "2\music.mp3" (Windows) or "2/music.mp3" (Linux)
            rel_path = os.path.relpath(absolute_path, root)
            parts = rel_path.split(os.sep)
            
            if not parts or parts[0] == '.':
                raise ValueError("Invalid path parsing")
                
            owner_id = int(parts[0])
            
            # Allow if user is owner OR user is admin
            if user['id'] != owner_id and not user['is_admin']:
                 logging.warning(f"[Media Debug] Access Denied. User {user['id']} tried to access Owner {owner_id}")
                 raise tornado.web.HTTPError(403, "Access Denied")
                 
        except ValueError:
             logging.error(f"[Media Debug] Could not parse owner ID from path: {rel_path}")
             raise tornado.web.HTTPError(403)

        return super().validate_absolute_path(root, absolute_path)

def make_app():
    return tornado.web.Application([
        # for certbot to get cert on Linux
        (
            r"/.well-known/acme-challenge/(.*)",
            tornado.web.StaticFileHandler,
            {"path": "/var/www/acme/.well-known/acme-challenge"}, 
        ),
        # --- NEW: Route for ads.txt and robots.txt ---
        (r"/(ads\.txt)", StaticRootFileHandler),
        (r"/(robots\.txt)", StaticRootFileHandler),
        # ---------------------------------------------
        # --- NEW: Media Streaming Route ---
        # Maps /media/ to the UPLOAD_ROOT (static/uploads)
        (r"/media/(.*)", ProtectedMediaHandler, {"path": UPLOAD_ROOT}),
        # ----------------------------------

        (r"/", DashboardHandler),
        # FIXED ROUTES BELOW: Using Regex Groups () to pass arguments
        (r"/(login)", AuthHandler),
        (r"/(register)", AuthHandler),
        (r"/(forgot)", AuthHandler),
        (r"/(logout)", AuthHandler),
        (r"/(captcha/.*)", AuthHandler), # Captures things like captcha/image
        (r"/files/action", FileActionHandler),
        (r"/files/download", DownloadHandler),
        (r"/share/(.*)", ShareHandler), 
        (r"/admin", AdminHandler),
        (r"/settings", UserSettingsHandler),
        (r"/source_code", SourceCodeHandler),
    ], 
    template_path=os.path.join(BASE_DIR, "templates"),
    static_path=os.path.join(BASE_DIR, "static"),
    cookie_secret=COOKIE_SECRET,
    login_url="/login",
    debug=True)

def setup_logging():
    """Configures the root logger to write to console and file."""
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)

    # Create formatters
    formatter = logging.Formatter('[%(asctime)s] [%(levelname)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

    # 1. Console Handler (Print to CMD)
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # 2. Rotating File Handler (Write to server.log)
    file_handler = RotatingFileHandler(LOG_FILE, maxBytes=LOG_MAX_BYTES, backupCount=LOG_BACKUP_COUNT)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    
    # Silence overly verbose libraries if needed
    logging.getLogger("tornado.access").setLevel(logging.INFO)

last_mtime = os.path.getmtime(SSL_CERT)
def check_cert():
    global last_mtime
    mtime = os.path.getmtime(SSL_CERT)
    if mtime > last_mtime:
        print("cert changed, restart...")
        executable = sys.executable if sys.executable else 'python3'
        os.execv(executable, [executable] + sys.argv)

if __name__ == "__main__":
    setup_logging()
    init_db()
    app = make_app()
    
    http_server = tornado.httpserver.HTTPServer(app)
    http_server.listen(PORT)
    logging.info(f"HTTP Server started at http://localhost:{PORT}")

    if SSL_ENABLED:
        ssl_options = {"certfile": SSL_CERT, "keyfile": SSL_KEY}
        https_server = tornado.httpserver.HTTPServer(app, ssl_options=ssl_options)
        https_server.listen(HTTPS_PORT)
        logging.info(f"HTTPS Server started at https://localhost:{HTTPS_PORT}")

    check_callback = tornado.ioloop.PeriodicCallback(check_cert, 60 * 60 * 1000)
    check_callback.start()

    tornado.ioloop.IOLoop.current().start()
