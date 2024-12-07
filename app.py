from flask import Flask, render_template, request, redirect, url_for, session, abort, jsonify
import os
import hashlib
import hmac
import json
import logging
from logging.handlers import RotatingFileHandler
import requests
from dotenv import load_dotenv
from datetime import datetime, timedelta
from models import db, UserLog

load_dotenv()

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Enable Flask debug mode and verbose logging
app.debug = True
app.config['PROPAGATE_EXCEPTIONS'] = True

# Setup logging
if not os.path.exists('logs'):
    os.mkdir('logs')
file_handler = RotatingFileHandler('logs/telegram_login.log', maxBytes=10240, backupCount=10)
file_handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
))
file_handler.setLevel(logging.DEBUG)  # Changed to DEBUG level
app.logger.addHandler(file_handler)
app.logger.setLevel(logging.DEBUG)  # Changed to DEBUG level

# Also log to console for development
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
))
console_handler.setLevel(logging.DEBUG)
app.logger.addHandler(console_handler)

app.logger.info('Telegram Login startup in debug mode')

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///user_logs.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)

# Create tables
with app.app_context():
    db.create_all()

# Get environment variables with defaults for testing
BOT_USERNAME = os.getenv('TELEGRAM_BOT_USERNAME')
WEBSITE_URL = os.getenv('WEBSITE_URL', 'http://localhost:5000')
ADMIN_USERNAME = os.getenv('ADMIN_USERNAME', 'maysam')
ADMIN_CHAT_ID = os.getenv('ADMIN_CHAT_ID')

def send_telegram_message(chat_id, message):
    """Send a message to a specific chat ID"""
    # Skip sending messages if we're in testing mode
    if app.config.get('TESTING'):
        app.logger.info(f"Test mode: Would have sent message to {chat_id}: {message}")
        return True

    bot_token = os.getenv('TELEGRAM_BOT_TOKEN')
    if not bot_token or bot_token.strip() == '':
        app.logger.error("Cannot send message: Bot token not configured")
        return False

    try:
        response = requests.post(
            f'https://api.telegram.org/bot{bot_token}/sendMessage',
            json={
                'chat_id': chat_id,
                'text': message,
                'parse_mode': 'HTML'
            }
        )

        if not response.ok:
            app.logger.error(f"Failed to send message: {response.text}")
            return False

        return True
    except Exception as e:
        app.logger.error(f"Error sending message: {str(e)}")
        return False

def get_visit_count(telegram_id):
    """Get the number of times a user has logged in"""
    return UserLog.query.filter_by(
        telegram_id=telegram_id,
        action='login'
    ).count()

def get_visit_message(count):
    """Generate a fun welcome message based on visit count"""
    if count == 1:
        return "Welcome aboard! 🚀 Excited to have you here for the first time!"
    elif count == 2:
        return "Welcome back! 👋 Great to see you again!"
    elif count <= 5:
        return f"Visit #{count}! 🌟 You're becoming a regular!"
    elif count <= 10:
        return f"Visit #{count}! 🏆 You're one of our most loyal visitors!"
    elif count <= 20:
        return f"Visit #{count}! 🎯 You're practically family now!"
    elif count == 42:
        return "Visit #42! 🌌 The answer to life, the universe, and everything!"
    elif count == 100:
        return "Visit #100! 🎉 Triple digits! You're a legend!"
    else:
        return f"Visit #{count}! 🌟 Always a pleasure to have you back!"

def get_goodbye_message(count):
    """Generate a fun goodbye message based on visit count"""
    if count == 1:
        return "Thanks for stopping by! 👋 Hope to see you again soon!"
    elif count == 2:
        return "Goodbye! 🌟 Thanks for coming back!"
    elif count <= 5:
        return f"Visit #{count} complete! 🚀 See you next time!"
    elif count <= 10:
        return f"Another great visit! 🏆 Can't wait for #{count + 1}!"
    elif count <= 20:
        return f"Visit #{count} in the books! 🎯 You're making this place awesome!"
    elif count == 42:
        return "So long, and thanks for all the fish! 🐬"
    elif count == 100:
        return "Visit #100 complete! 🎉 You're officially a superstar!"
    else:
        return f"Visit #{count} complete! 🌟 Until we meet again!"

def send_login_notifications(user_data):
    """Send login notifications to both admin and user"""
    # Get visit count
    visit_count = get_visit_count(user_data['id'])

    # Admin notification
    admin_chat_id = os.getenv('ADMIN_CHAT_ID')
    if admin_chat_id:
        admin_message = (
            f"🔵 New login:\n"
            f"User: {user_data['first_name']}"
            f"{' (@' + user_data['username'] + ')' if user_data.get('username') else ''}\n"
            f"ID: {user_data['id']}\n"
            f"Visit count: #{visit_count}"
        )
        send_telegram_message(admin_chat_id, admin_message)

    # User notification
    user_message = get_visit_message(visit_count)
    if user_data.get('id'):
        send_telegram_message(user_data['id'], user_message)

def send_logout_notifications(user_data):
    """Send logout notifications to both admin and user"""
    # Get visit count
    visit_count = get_visit_count(user_data['id'])

    # Admin notification
    admin_chat_id = os.getenv('ADMIN_CHAT_ID')
    if admin_chat_id:
        admin_message = (
            f"🔴 User logged out:\n"
            f"User: {user_data['first_name']}"
            f"{' (@' + user_data['username'] + ')' if user_data.get('username') else ''}\n"
            f"ID: {user_data['id']}\n"
            f"Total visits: {visit_count}"
        )
        send_telegram_message(admin_chat_id, admin_message)

    # User notification
    user_message = get_goodbye_message(visit_count)
    if user_data.get('id'):
        send_telegram_message(user_data['id'], user_message)

def verify_telegram_data(data):
    """Verify that the data received from Telegram is authentic"""
    app.logger.debug("Starting data verification with data: %s", data)

    bot_token = os.getenv('TELEGRAM_BOT_TOKEN')
    if not bot_token or bot_token.strip() == '':
        app.logger.error("Verification failed: Bot token not configured")
        return None

    if not data.get('hash'):
        app.logger.error("Verification failed: No hash provided in data")
        return False

    # Make a copy of the data dict to avoid modifying the original
    auth_data = data.copy()
    received_hash = auth_data.pop('hash')

    app.logger.debug("Auth data after removing hash: %s", auth_data)
    app.logger.debug("Received hash: %s", received_hash)
    app.logger.debug("Bot token (first 4 chars): %s...", bot_token[:4])

    # Create data-check-string
    check_arr = []
    for key in sorted(auth_data.keys()):
        value = auth_data[key]
        if value:  # Only include non-empty values
            # Convert all values to strings and escape special characters
            check_arr.append(f"{key}={value}")
            app.logger.debug("Added to check array: %s=%s", key, value)

    # Join with newlines
    data_check_string = '\n'.join(check_arr)
    app.logger.debug("Data check string: %s", data_check_string)

    # First, create SHA256 hash of bot token
    secret_key = hashlib.sha256(bot_token.encode('utf-8')).digest()
    app.logger.debug("Secret key (SHA256 of bot token) first 4 bytes: %s", secret_key[:4].hex())

    # Then use it as a key for HMAC-SHA256
    calculated_hash = hmac.new(
        key=secret_key,
        msg=data_check_string.encode('utf-8'),
        digestmod=hashlib.sha256
    ).hexdigest()

    app.logger.debug("Calculated hash: %s", calculated_hash)
    app.logger.debug("Hash comparison: calculated(%s) == received(%s)", calculated_hash, received_hash)

    result = calculated_hash == received_hash
    app.logger.info("Verification result: %s", result)
    return result

@app.route('/', methods=['GET', 'POST'])
def index():
    bot_token = os.getenv('TELEGRAM_BOT_TOKEN')
    if not bot_token or bot_token.strip() == '':
        return render_template('index.html',
                             error="Telegram bot not properly configured. Please set up your environment variables.",
                             bot_username=None,
                             admin_username=ADMIN_USERNAME)
    return render_template('index.html',
                         user=session.get('user'),
                         bot_username=BOT_USERNAME,
                         admin_username=ADMIN_USERNAME,
                         error=request.args.get('error'))

@app.route('/login/telegram', methods=['POST'])
def telegram_login():
    """Handle Telegram login"""
    app.logger.debug("Raw request data: %s", request.get_data(as_text=True))
    app.logger.debug("Request form: %s", request.form)
    app.logger.debug("Request args: %s", request.args)
    app.logger.debug("Request values: %s", request.values)

    bot_token = os.getenv('TELEGRAM_BOT_TOKEN')
    if not bot_token or bot_token.strip() == '':
        app.logger.error("Telegram login failed: Bot token not configured")
        return redirect(url_for('index', error="Telegram bot not properly configured"))

    # Log raw form data for debugging
    app.logger.info("Raw form data:")
    app.logger.info(json.dumps(dict(request.form), indent=2))

    # Get data from form with proper field mapping
    data = {
        'id': request.form.get('id'),
        'first_name': request.form.get('first_name'),
        'last_name': request.form.get('last_name'),
        'username': request.form.get('username'),
        'photo_url': request.form.get('photo_url'),
        'auth_date': request.form.get('auth_date'),
        'hash': request.form.get('hash')
    }

    # Remove None values (but keep empty strings)
    data = {k: v for k, v in data.items() if v is not None}

    app.logger.info("Processed login data:")
    app.logger.info(json.dumps(data, indent=2))

    # Verify the authentication data
    verification_result = verify_telegram_data(data)
    app.logger.info(f"Verification result: {verification_result}")

    if not verification_result:
        app.logger.error("Telegram login failed: Invalid authentication data")
        app.logger.error(f"Auth data: {json.dumps(data, indent=2)}")
        return redirect(url_for('index', error="Invalid authentication data"))

    # Store user data in session
    session['user'] = {
        'id': data['id'],
        'first_name': data['first_name'],
        'last_name': data.get('last_name', ''),
        'username': data.get('username', ''),
        'photo_url': data.get('photo_url', '')
    }

    # Set session expiry to 24 hours if remember_me is checked
    if request.form.get('remember_me'):
        session.permanent = True
        app.permanent_session_lifetime = timedelta(days=1)
    else:
        session.permanent = False

    # Log the login
    try:
        log_entry = UserLog(
            telegram_id=data['id'],
            first_name=data['first_name'],
            username=data.get('username'),
            action='login'
        )
        db.session.add(log_entry)
        db.session.commit()
    except Exception as e:
        app.logger.error(f"Failed to log login: {str(e)}")

    # Send notifications
    try:
        send_login_notifications(data)
    except Exception as e:
        app.logger.error(f"Failed to send login notifications: {str(e)}")

    return redirect(url_for('index'))

@app.route('/logout')
def logout():
    user_data = session.get('user')
    if user_data and 'id' in user_data and 'first_name' in user_data:
        # Log the logout
        log_entry = UserLog(
            telegram_id=user_data['id'],
            first_name=user_data['first_name'],
            username=user_data.get('username'),
            action='logout'
        )
        db.session.add(log_entry)
        db.session.commit()

        # Send notifications
        send_logout_notifications(user_data)

    # Clear the session
    session.pop('user', None)
    return redirect(url_for('index'))

def is_admin():
    """Check if the current user is an admin"""
    user = session.get('user')
    return user and user.get('username') == ADMIN_USERNAME

@app.route('/admin')
def admin_panel():
    if not is_admin():
        return redirect(url_for('index'))

    # Get all logs, ordered by timestamp (newest first)
    logs = UserLog.query.order_by(UserLog.timestamp.desc()).all()
    return render_template('admin.html', logs=logs)

@app.route('/api/logs')
def get_logs():
    if not is_admin():
        return jsonify({'error': 'Unauthorized'}), 401

    # Get all logs, ordered by timestamp (newest first)
    logs = UserLog.query.order_by(UserLog.timestamp.desc()).all()
    return jsonify([log.to_dict() for log in logs])

@app.route('/api/clean-logs', methods=['POST'])
def clean_logs():
    if not is_admin():
        abort(403)

    try:
        UserLog.query.delete()
        db.session.commit()
        return jsonify({'status': 'success', 'message': 'All logs have been cleared'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.errorhandler(404)
def page_not_found(e):
    """Handle 404 errors by showing a custom error page"""
    # Log the 404 error
    app.logger.warning(f'404 Error: {request.url}')
    return render_template('404.html'), 404

if __name__ == '__main__':
    bot_token = os.getenv('TELEGRAM_BOT_TOKEN')
    if not bot_token or bot_token.strip() == '':
        print("Please set up your .env file with TELEGRAM_BOT_TOKEN and TELEGRAM_BOT_USERNAME")
    app.run(debug=True)
