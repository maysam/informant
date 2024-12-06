from flask import Flask, render_template, request, redirect, url_for, session, abort, jsonify
import os
import hashlib
import hmac
import json
import requests
from dotenv import load_dotenv
from datetime import datetime

load_dotenv()

app = Flask(__name__)
app.secret_key = os.urandom(24)

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

def send_login_notifications(user_data):
    """Send login notifications to both admin and user"""
    # Admin notification
    admin_message = f""" New Login Alert!
User: {user_data.get('first_name', 'Unknown')}
Username: @{user_data.get('username', 'Unknown')}
Telegram ID: {user_data.get('id', 'Unknown')}
Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"""

    if ADMIN_CHAT_ID:
        send_telegram_message(ADMIN_CHAT_ID, admin_message)

    # User notification
    user_message = f""" Welcome, {user_data.get('first_name', 'Unknown')}!
You have successfully logged in to {WEBSITE_URL}
Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Enjoy your session! """

    if user_data.get('id'):
        send_telegram_message(user_data.get('id'), user_message)

def send_logout_notifications(user_data):
    """Send logout notifications to both admin and user"""
    # Admin notification
    admin_message = f""" Logout Alert!
User: {user_data.get('first_name', 'Unknown')}
Username: @{user_data.get('username', 'Unknown')}
Telegram ID: {user_data.get('id', 'Unknown')}
Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"""

    if ADMIN_CHAT_ID:
        send_telegram_message(ADMIN_CHAT_ID, admin_message)

    # User notification
    user_message = f""" Goodbye, {user_data.get('first_name', 'Unknown')}!
You have successfully logged out from {WEBSITE_URL}
Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Thanks for visiting! See you next time! """

    if user_data.get('id'):
        send_telegram_message(user_data.get('id'), user_message)

def verify_telegram_data(data):
    """Verify that the data received from Telegram is authentic"""
    bot_token = os.getenv('TELEGRAM_BOT_TOKEN')
    if not bot_token or bot_token.strip() == '':
        return None
        
    if not data.get('hash'):
        return False
    
    received_hash = data['hash']
    data_check_list = []
    
    for key, value in sorted(data.items()):
        if key != 'hash':
            data_check_list.append(f"{key}={value}")
    
    data_check_string = '\n'.join(data_check_list)
    secret_key = hashlib.sha256(bot_token.encode()).digest()
    calculated_hash = hmac.new(
        secret_key,
        data_check_string.encode(),
        hashlib.sha256
    ).hexdigest()
    
    return calculated_hash == received_hash

@app.route('/')
def index():
    bot_token = os.getenv('TELEGRAM_BOT_TOKEN')
    if not bot_token or bot_token.strip() == '':
        return render_template('index.html', 
                             error="Telegram bot not properly configured. Please set up your environment variables.",
                             bot_username=None)
    return render_template('index.html', 
                         user=session.get('user'), 
                         bot_username=BOT_USERNAME,
                         error=None)

@app.route('/login/telegram', methods=['POST'])
def telegram_login():
    bot_token = os.getenv('TELEGRAM_BOT_TOKEN')
    if not bot_token or bot_token.strip() == '':
        return 'Telegram bot token not configured', 500
        
    # Get form data
    data = request.form.to_dict()
    if not data:
        return 'No data received', 500
        
    # Verify the data
    verification_result = verify_telegram_data(data)
    if verification_result is None:
        return 'Telegram bot token not configured', 500
        
    if not verification_result:
        return 'Authentication failed', 401
        
    # Create user data
    user_data = {
        'id': data.get('id'),
        'first_name': data.get('first_name'),
        'username': data.get('username'),
        'photo_url': data.get('photo_url'),
        'auth_date': data.get('auth_date')
    }
    
    # Store in session
    session['user'] = user_data
    
    # Send notifications
    send_login_notifications(user_data)
    
    return redirect(url_for('index'))

@app.route('/logout')
def logout():
    user_data = session.get('user')
    if user_data:
        # Send notifications before clearing the session
        send_logout_notifications(user_data)
    session.pop('user', None)
    return redirect(url_for('index'))

if __name__ == '__main__':
    bot_token = os.getenv('TELEGRAM_BOT_TOKEN')
    if not bot_token or bot_token.strip() == '':
        print("Please set up your .env file with TELEGRAM_BOT_TOKEN and TELEGRAM_BOT_USERNAME")
    app.run(debug=True)
