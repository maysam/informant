import pytest
from app import app, verify_telegram_data
import os
import time
import hashlib
import hmac

@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['SECRET_KEY'] = 'test_secret_key'
    with app.test_client() as client:
        yield client

@pytest.fixture
def mock_env(monkeypatch):
    """Fixture to set up test environment variables"""
    test_token = 'test_token'
    test_username = 'test_bot'
    monkeypatch.setenv('TELEGRAM_BOT_TOKEN', test_token)
    monkeypatch.setenv('TELEGRAM_BOT_USERNAME', test_username)
    monkeypatch.setenv('WEBSITE_URL', 'http://localhost:5000')
    # Also set the app variables directly since they're already loaded
    monkeypatch.setattr('app.BOT_TOKEN', test_token)
    monkeypatch.setattr('app.BOT_USERNAME', test_username)
    return {'token': test_token, 'username': test_username}

def test_index_page(client):
    """Test that the index page loads correctly"""
    response = client.get('/')
    assert response.status_code == 200
    assert b'Welcome to Telegram Login Demo' in response.data

def test_index_with_user(client):
    """Test index page when user is logged in"""
    with client.session_transaction() as session:
        session['user'] = {
            'id': '12345',
            'first_name': 'Test User',
            'username': 'testuser',
            'photo_url': 'http://example.com/photo.jpg',
            'auth_date': str(int(time.time()))
        }
    
    response = client.get('/')
    assert response.status_code == 200
    assert b'Welcome, Test User!' in response.data

def test_logout(client):
    """Test logout functionality"""
    with client.session_transaction() as session:
        session['user'] = {'id': '12345', 'first_name': 'Test User'}
    
    response = client.get('/logout', follow_redirects=True)
    assert response.status_code == 200
    
    # Check that session is cleared
    with client.session_transaction() as session:
        assert 'user' not in session

def create_telegram_hash(data, bot_token):
    """Helper function to create Telegram authentication hash"""
    data_check_list = []
    for key, value in sorted(data.items()):
        if key != 'hash':
            data_check_list.append(f"{key}={value}")
    
    data_check_string = '\n'.join(data_check_list)
    secret_key = hashlib.sha256(bot_token.encode()).digest()
    return hmac.new(
        secret_key,
        data_check_string.encode(),
        hashlib.sha256
    ).hexdigest()

def test_verify_telegram_data(mock_env):
    """Test the Telegram data verification function"""
    # Test with valid data
    valid_data = {
        'id': '12345',
        'first_name': 'Test',
        'username': 'testuser',
        'auth_date': str(int(time.time()))
    }
    valid_data['hash'] = create_telegram_hash(valid_data, mock_env['token'])
    assert verify_telegram_data(valid_data) == True
    
    # Test with invalid hash
    invalid_data = valid_data.copy()
    invalid_data['hash'] = 'invalid_hash'
    assert verify_telegram_data(invalid_data) == False
    
    # Test with missing hash
    no_hash_data = valid_data.copy()
    del no_hash_data['hash']
    assert verify_telegram_data(no_hash_data) == False

def test_telegram_login_invalid_data(client, mock_env):
    """Test login with invalid Telegram data"""
    invalid_data = {
        'id': '12345',
        'first_name': 'Test',
        'username': 'testuser',
        'auth_date': str(int(time.time())),
        'hash': 'invalid_hash'
    }
    
    response = client.post('/login/telegram', data=invalid_data)
    assert response.status_code == 401
    
    # Verify user is not in session
    with client.session_transaction() as session:
        assert 'user' not in session

def test_telegram_login_valid_data(client, mock_env):
    """Test login with valid Telegram data"""
    valid_data = {
        'id': '12345',
        'first_name': 'Test',
        'username': 'testuser',
        'auth_date': str(int(time.time()))
    }
    valid_data['hash'] = create_telegram_hash(valid_data, mock_env['token'])
    
    response = client.post('/login/telegram', data=valid_data, follow_redirects=True)
    assert response.status_code == 200
    
    # Verify user is in session
    with client.session_transaction() as session:
        assert 'user' in session
        assert session['user']['id'] == '12345'
        assert session['user']['first_name'] == 'Test'

def test_telegram_login_no_token_configured(client, monkeypatch):
    """Test login attempt when no bot token is configured"""
    # Clear both environment variable and app variable
    monkeypatch.setenv('TELEGRAM_BOT_TOKEN', '')
    monkeypatch.setattr('app.BOT_TOKEN', None)
    
    valid_data = {
        'id': '12345',
        'first_name': 'Test',
        'username': 'testuser',
        'auth_date': str(int(time.time())),
        'hash': 'some_hash'
    }
    
    response = client.post('/login/telegram', data=valid_data, follow_redirects=False)
    assert response.status_code == 500
    assert b'Telegram bot token not configured' in response.data
