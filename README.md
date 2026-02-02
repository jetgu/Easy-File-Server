# ☁️ Easy File Server

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Framework](https://img.shields.io/badge/Framework-Tornado-orange.svg)](https://www.tornadoweb.org/)

**Easy File Server** is a robust, open-source, self-hosted cloud storage solution. It provides a Google Drive-like experience on your own machine, allowing you to store, edit, stream, and share files securely. Built with Python Tornado for high performance and low latency.

![Demo website](https://sharing-file.com)


## ✨ Features

### 📂 File Management
*   **Full Control:** Upload, Download, Delete, Rename, and Create New Files/Folders.
*   **Clipboard:** Copy, Cut, and Paste files across directories.
*   **Zip Operations:** Zip folders for easy download or Unzip archives online.
*   **Online Editor:** Edit Text, Python, HTML, and other code files directly in the browser.

### 🎬 Media & Streaming
*   **Video/Audio Player:** Stream MP4, MP3, and other media formats with seeking support (HTTP Range Requests).
*   **Image Gallery:** Grid view with thumbnail previews.

### 🔒 Security & Sharing
*   **Secure Sharing:** Generate public share links with expiration dates (1, 3, 7, or 30 days).
*   **User Isolation:** Each user has a private directory that cannot be accessed by others.
*   **Disk Quotas:** Admin can set storage limits (default 5GB) per user.
*   **Authentication:** Secure login with Bcrypt hashing and CAPTCHA protection.

### 🛠️ Administration
*   **User Management:** Enable/Disable users, reset passwords, and adjust quotas.
*   **Impersonation:** Admins can view and manage user files to offer support.
*   **System Settings:** Configure global upload limits and download speeds.

## 🚀 Getting Started

### Prerequisites
*   Python 3.8 or higher
*   pip (Python Package Manager)

### Installation

1.  **Clone the repository**
    ```bash
    git clone https://github.com/yourusername/easy-file-server.git
    cd easy-file-server
    ```

2.  **Create a Virtual Environment (Recommended)**
    ```bash
    # Windows
    python -m venv venv
    venv\Scripts\activate

    # Linux/Mac
    python3 -m venv venv
    source venv/bin/activate
    ```

3.  **Install Dependencies**
    ```bash
    pip install -r requirements.txt
    ```

4.  **Download Static Assets**
    This script downloads Bootstrap 5 and Icons to run the server locally without external CDNs.
    ```bash
    python setup_assets.py
    ```

5.  **Run the Server**
    ```bash
    python app.py
    ```
    The server will start at: `http://localhost:8888`

---

## 🔑 Default Credentials

A default administrator account is created on the first run:

*   **Email:** `admin@example.com`
*   **Password:** `admin123`

> ⚠️ **IMPORTANT:** Log in immediately and change the password in the **Settings** page.

---

## ⚙️ Configuration

You can customize the server by editing `config.py`:

*   **SSL/HTTPS:** Set `SSL_ENABLED = True` and provide path to `.crt` and `.key` files.
*   **SMTP Email:** Configure `SMTP_USER` and `SMTP_PASS` (App Password) to enable "Forgot Password" emails.
*   **Logging:** Logs are saved to `server.log`.

## 🏗️ Project Structure

```text
easy-file-server/
├── app.py              # Main application entry point & logic
├── config.py           # Configuration settings
├── database.py         # SQLite database handling
├── utils.py            # Helper functions (Captcha, Zipping, Security)
├── setup_assets.py     # Script to download static assets
├── static/             # CSS, JS, Fonts, and User Uploads
├── templates/          # HTML Templates (Jinja2-style)
└── requirements.txt    # Python dependencies
