from flask import Flask, render_template, request, redirect, url_for, session, abort
import os
import hashlib
import hmac
import json
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Get environment variables with defaults for testing
BOT_TOKEN = os.getenv('TELEGRAM_BOT_TOKEN')
BOT_USERNAME = os.getenv('TELEGRAM_BOT_USERNAME')
WEBSITE_URL = os.getenv('WEBSITE_URL', 'http://localhost:5000')

def verify_telegram_data(data):
    """Verify that the data received from Telegram is authentic"""
    if not BOT_TOKEN or BOT_TOKEN.strip() == '':
        return None
        
    if not data.get('hash'):
        return False
    
    received_hash = data['hash']
    data_check_list = []
    
    for key, value in sorted(data.items()):
        if key != 'hash':
            data_check_list.append(f"{key}={value}")
    
    data_check_string = '\n'.join(data_check_list)
    secret_key = hashlib.sha256(BOT_TOKEN.encode()).digest()
    calculated_hash = hmac.new(
        secret_key,
        data_check_string.encode(),
        hashlib.sha256
    ).hexdigest()
    
    return calculated_hash == received_hash

@app.route('/')
def index():
    if not BOT_TOKEN or BOT_TOKEN.strip() == '':
        return render_template('index.html', error="Telegram bot not properly configured. Please set up your environment variables.")
    user = session.get('user')
    return render_template('index.html', user=user, bot_username=BOT_USERNAME)

@app.route('/login/telegram', methods=['POST'])
def telegram_login():
    if not BOT_TOKEN or BOT_TOKEN.strip() == '':
        return 'Telegram bot token not configured', 500
        
    data = request.form.to_dict()
    verification_result = verify_telegram_data(data)
    
    if verification_result is None:
        return 'Telegram bot token not configured', 500
    elif verification_result:
        session['user'] = {
            'id': data.get('id'),
            'first_name': data.get('first_name'),
            'username': data.get('username'),
            'photo_url': data.get('photo_url'),
            'auth_date': data.get('auth_date')
        }
        return redirect(url_for('index'))
    
    return 'Authentication failed', 401

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('index'))

if __name__ == '__main__':
    if not BOT_TOKEN or BOT_TOKEN.strip() == '':
        print("Please set up your .env file with TELEGRAM_BOT_TOKEN and TELEGRAM_BOT_USERNAME")
    app.run(debug=True)
