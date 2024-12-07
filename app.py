from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
import hashlib
import hmac
import json
import logging
from logging.handlers import RotatingFileHandler
import os
import requests
from dotenv import load_dotenv
from datetime import datetime, timedelta
from models import db, UserLog, TelegramUser, Group

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
    """Send login notification to the user"""
    if not user_data:
        return

    telegram_id = user_data.get('id')
    if not telegram_id:
        return

    visit_count = get_visit_count(telegram_id)
    message = get_visit_message(visit_count)
    send_telegram_message(telegram_id, message)

def send_logout_notifications(user_data):
    """Send logout notification to the user"""
    if not user_data:
        return

    telegram_id = user_data.get('id')
    if not telegram_id:
        return

    visit_count = get_visit_count(telegram_id)
    message = get_goodbye_message(visit_count)
    send_telegram_message(telegram_id, message)

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

def is_admin():
    """Check if the current user is an admin"""
    if not session.get('user'):
        return False
    return session['user'].get('username') == ADMIN_USERNAME

@app.route('/', methods=['GET', 'POST'])
def index():
    bot_token = os.getenv('TELEGRAM_BOT_TOKEN')
    if not bot_token or bot_token.strip() == '':
        return render_template('index.html',
                             error="Telegram bot not properly configured. Please set up your environment variables.",
                             bot_username=None)
    return render_template('index.html',
                         user=session.get('user'),
                         bot_username=BOT_USERNAME,
                         error=request.args.get('error'))

@app.route('/login/telegram', methods=['POST'])
def telegram_login():
    """Handle Telegram login callback"""
    try:
        # Parse user data from form
        data = {}
        for key in ['id', 'first_name', 'last_name', 'username', 'photo_url', 'auth_date', 'hash']:
            data[key] = request.form.get(key)

        app.logger.info("Parsed user data: %s", data)

        # Basic validation
        if not all(key in data for key in ['id', 'first_name', 'auth_date', 'hash']):
            app.logger.error("Missing required fields")
            return redirect(url_for('index', error='Authentication failed'))

        # Verify the authentication
        if not verify_telegram_data(data):
            app.logger.error("Data verification failed")
            return redirect(url_for('index', error='Authentication failed'))

        # Convert id and auth_date to integers
        try:
            data['id'] = int(data['id'])
            data['auth_date'] = int(data['auth_date'])
        except (ValueError, TypeError):
            app.logger.error("Invalid ID or auth_date format")
            return redirect(url_for('index', error='Authentication failed'))

        # Check if user exists
        user = TelegramUser.query.filter_by(telegram_id=data['id']).first()

        if user:
            # Update existing user
            user.username = data.get('username')
            user.first_name = data['first_name']
            user.last_name = data.get('last_name')
            user.photo_url = data.get('photo_url')
            user.auth_date = data['auth_date']  # Update auth_date
            user.last_seen = datetime.utcnow()
        else:
            # Create new user
            user = TelegramUser(
                telegram_id=data['id'],
                username=data.get('username'),
                first_name=data['first_name'],
                last_name=data.get('last_name'),
                photo_url=data.get('photo_url'),
                auth_date=data['auth_date'],  # Set auth_date
                hash=data['hash']
            )
            db.session.add(user)

        # Save changes
        db.session.commit()

        # Store user info in session
        session['user'] = {
            'id': user.telegram_id,
            'first_name': user.first_name,
            'username': user.username,
            'photo_url': user.photo_url
        }

        # Handle remember me
        if request.form.get('remember_me') == 'on':
            session.permanent = True
            # Set session lifetime to 30 days
            app.permanent_session_lifetime = timedelta(days=30)

        # Log the login
        log = UserLog(
            telegram_id=user.telegram_id,
            first_name=user.first_name,
            username=user.username,
            action='login'
        )
        db.session.add(log)
        db.session.commit()

        # Send notifications
        send_login_notifications(session['user'])

        return redirect(url_for('index'))

    except Exception as e:
        app.logger.error("Error in login: %s", str(e), exc_info=True)
        return redirect(url_for('index', error='Authentication failed'))

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

@app.route('/manage_groups', methods=['GET', 'POST'])
def manage_groups():
    if not session.get('user'):
        return redirect(url_for('index', error='Please login first'))

    if request.method == 'POST':
        action = request.form.get('action')
        group_id = request.form.get('group_id')
        
        if action == 'create':
            group_name = request.form.get('group_name')
            if group_name:
                group = Group(
                    name=group_name,
                    owner_id=session['user']['id']
                )
                db.session.add(group)
                db.session.commit()
                flash('Group created successfully!', 'success')
        
        elif action == 'add_member':
            group = Group.query.get(group_id)
            if group and group.owner_id == session['user']['id']:
                member_name = request.form.get('member_name')
                if member_name:
                    group.add_member(member_name)
                    db.session.commit()
                    flash(f'Member {member_name} added to group!', 'success')
            else:
                flash('Access denied!', 'error')
        
        elif action == 'remove_member':
            group = Group.query.get(group_id)
            if group and group.owner_id == session['user']['id']:
                member_name = request.form.get('member_name')
                if member_name:
                    group.remove_member(member_name)
                    db.session.commit()
                    flash(f'Member {member_name} removed from group!', 'success')
            else:
                flash('Access denied!', 'error')
        
        elif action == 'delete':
            group = Group.query.get(group_id)
            if group and group.owner_id == session['user']['id']:
                db.session.delete(group)
                db.session.commit()
                flash('Group deleted successfully!', 'success')
            else:
                flash('Access denied!', 'error')

    # Only show groups owned by the current user
    groups = Group.query.filter_by(owner_id=session['user']['id']).all()
    return render_template('manage_groups.html', groups=groups)

@app.route('/api/users/<int:user_id>/toggle-permissions', methods=['POST'])
def toggle_user_permissions(user_id):
    if not session.get('user'):
        return jsonify({'success': False, 'message': 'Not logged in'}), 401

    user = TelegramUser.query.filter_by(telegram_id=user_id).first()
    if not user:
        return jsonify({'success': False, 'message': 'User not found'}), 404

    # Only allow users to toggle their own permissions
    if user.telegram_id != session['user']['id']:
        return jsonify({'success': False, 'message': 'Not authorized'}), 403

    user.can_send_messages = not user.can_send_messages
    db.session.commit()

    return jsonify({
        'success': True,
        'message': f'Message permissions {"enabled" if user.can_send_messages else "disabled"}'
    })

@app.route('/api/groups', methods=['POST'])
def create_group():
    if not session.get('user'):
        return jsonify({'success': False, 'message': 'Not logged in'}), 401

    data = request.get_json()
    name = data.get('name')
    members = data.get('members', [])

    if not name:
        return jsonify({'success': False, 'message': 'Group name is required'}), 400

    # Create new group
    group = Group(
        name=name,
        owner_id=session['user']['id']
    )
    
    # Add members to group
    for member in members:
        group.add_member(member)

    db.session.add(group)
    db.session.commit()

    return jsonify({
        'success': True,
        'message': 'Group created successfully',
        'group': {
            'id': group.id,
            'name': group.name,
            'members': group.get_members()
        }
    })

@app.route('/api/groups/<int:group_id>', methods=['DELETE'])
def delete_group(group_id):
    if not session.get('user'):
        return jsonify({'success': False, 'message': 'Not logged in'}), 401

    group = Group.query.get(group_id)
    if not group:
        return jsonify({'success': False, 'message': 'Group not found'}), 404

    # Only allow group creator to delete the group
    if group.owner_id != session['user']['id']:
        return jsonify({'success': False, 'message': 'Not authorized'}), 403

    db.session.delete(group)
    db.session.commit()

    return jsonify({
        'success': True,
        'message': 'Group deleted successfully'
    })

@app.route('/api/send-message', methods=['POST'])
def send_message():
    if not session.get('user'):
        return jsonify({'success': False, 'message': 'Not logged in'}), 401

    data = request.get_json()
    message = data.get('message')
    user_ids = data.get('users', [])
    group_ids = data.get('groups', [])

    if not message:
        return jsonify({'success': False, 'message': 'Message is required'}), 400

    if not user_ids and not group_ids:
        return jsonify({'success': False, 'message': 'Select at least one recipient'}), 400

    sender = TelegramUser.query.filter_by(telegram_id=session['user']['id']).first()
    if not sender:
        return jsonify({'success': False, 'message': 'Sender not found'}), 404

    # Get all members from selected groups (only from groups owned by the current user)
    group_members = set()
    if group_ids:
        groups = Group.query.filter(
            Group.id.in_(group_ids),
            Group.owner_id == session['user']['id']
        ).all()
        for group in groups:
            group_members.update(group.get_members())

    # Send message to all recipients
    success_count = 0
    failed_recipients = []

    # Send to individual users
    for user_id in user_ids:
        try:
            send_telegram_message(user_id, message)
            success_count += 1
        except Exception as e:
            failed_recipients.append(str(user_id))

    # Send to group members (implement your logic to send to group members)
    for member_name in group_members:
        try:
            # Here you would need to implement how to send messages to members
            # since they are now stored as strings, not user IDs
            # This might require additional user input or mapping
            pass
        except Exception as e:
            failed_recipients.append(member_name)

    response_message = f"Message sent to {success_count} recipient(s)"
    if failed_recipients:
        response_message += f"\nFailed to send to: {', '.join(failed_recipients)}"

    return jsonify({
        'success': True,
        'message': response_message
    })

@app.route('/logs')
def view_logs():
    """View all user login history (admin only)"""
    if not session.get('user'):
        return redirect(url_for('index', error='Please login first'))

    if not is_admin():
        return redirect(url_for('index', error='Access denied'))

    # Get all logs
    logs = UserLog.query.order_by(UserLog.timestamp.desc()).all()

    return render_template('logs.html', logs=logs)

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
