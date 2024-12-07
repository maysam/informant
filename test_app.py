import os
import pytest
from app import app
from app import UserLog, db
import json

@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['SECRET_KEY'] = 'test_secret_key'
    with app.test_client() as client:
        yield client

@pytest.fixture
def mock_env_vars(monkeypatch):
    """Fixture to set test environment variables"""
    test_token = 'test_token'
    test_username = 'test_bot'
    monkeypatch.setenv('TELEGRAM_BOT_TOKEN', test_token)
    monkeypatch.setenv('TELEGRAM_BOT_USERNAME', test_username)
    yield {'token': test_token, 'username': test_username}

@pytest.fixture
def clear_env_vars(monkeypatch):
    """Fixture to clear environment variables"""
    monkeypatch.delenv('TELEGRAM_BOT_TOKEN', raising=False)
    monkeypatch.delenv('TELEGRAM_BOT_USERNAME', raising=False)
    yield

@pytest.fixture
def clean_db(client):
    """Clean the database before each test that uses this fixture"""
    with client.application.app_context():
        db.drop_all()
        db.create_all()
    yield
    with client.application.app_context():
        db.drop_all()

def test_index_page(client, mock_env_vars):
    """Test that the index page loads correctly"""
    response = client.get('/')
    assert response.status_code == 200
    assert b'Welcome to Telegram Login' in response.data

def test_index_with_user(client, mock_env_vars):
    """Test index page with logged in user"""
    with client.session_transaction() as session:
        session['user'] = {
            'first_name': 'Test',
            'username': 'testuser'
        }
    response = client.get('/')
    assert b'Welcome, Test!' in response.data

def test_logout(client, mock_env_vars):
    """Test logout functionality"""
    with client.session_transaction() as session:
        session['user'] = {
            'id': 12345,
            'first_name': 'Test',
            'username': 'testuser'
        }
    response = client.get('/logout')
    assert response.status_code == 302
    with client.session_transaction() as session:
        assert 'user' not in session

def test_verify_telegram_data(mock_env_vars):
    """Test Telegram data verification"""
    from app import verify_telegram_data
    test_data = {'key': 'value', 'hash': 'invalid'}
    assert verify_telegram_data(test_data) is False

def test_telegram_login_invalid_data(client, mock_env_vars):
    """Test login with invalid data"""
    data = {'hash': 'invalid'}
    response = client.post('/login/telegram', data=data)
    assert response.status_code == 302
    assert 'error=Invalid+authentication+data' in response.headers['Location']

def test_telegram_login_valid_data(client, mock_env_vars, monkeypatch):
    """Test login with valid data"""
    def mock_verify(data):
        return True
    monkeypatch.setattr('app.verify_telegram_data', mock_verify)
    
    data = {
        'user_id': '123456',  # Changed from 'id' to 'user_id'
        'first_name': 'Test',
        'username': 'testuser',
        'photo_url': 'http://example.com/photo.jpg',
        'auth_date': '1234567890',
        'hash': 'valid_hash'
    }
    response = client.post('/login/telegram', data=data)
    assert response.status_code == 302

def test_telegram_login_no_token_configured(client, clear_env_vars):
    """Test login attempt without bot token configured"""
    data = {'hash': 'test'}
    response = client.post('/login/telegram', data=data)
    assert response.status_code == 302
    assert 'error=Telegram+bot+not+properly+configured' in response.headers['Location']

def test_index_without_bot_token(client, clear_env_vars):
    """Test index page without bot token configured"""
    response = client.get('/')
    assert b'Telegram bot not properly configured' in response.data

def test_login_without_bot_token(client, clear_env_vars):
    """Test login without bot token configured"""
    response = client.post('/login/telegram')
    assert response.status_code == 302
    assert 'error=Telegram+bot+not+properly+configured' in response.headers['Location']

def test_successful_login(client, mock_env_vars, monkeypatch):
    """Test successful login flow"""
    def mock_verify(data):
        return True
    monkeypatch.setattr('app.verify_telegram_data', mock_verify)
    
    data = {
        'user_id': '123456',  # Changed from 'id' to 'user_id'
        'first_name': 'Test',
        'username': 'testuser',
        'photo_url': 'http://example.com/photo.jpg',
        'auth_date': '1234567890',
        'hash': 'valid_hash'
    }
    response = client.post('/login/telegram', data=data)
    assert response.status_code == 302

def test_login_with_remember_me(client, mock_env_vars, monkeypatch):
    """Test login with remember me option"""
    # Mock verify_telegram_data to return True
    monkeypatch.setattr('app.verify_telegram_data', lambda x: True)
    
    # Test data
    data = {
        'user_id': '12345',  # Changed from 'id' to 'user_id'
        'first_name': 'Test',
        'username': 'testuser',
        'photo_url': 'https://example.com/photo.jpg',
        'auth_date': '1234567890',
        'hash': 'testhash',
        'remember_me': 'on'
    }
    
    response = client.post('/login/telegram', data=data)
    assert response.status_code == 302
    
    # Check if session is permanent and has correct lifetime
    with client.session_transaction() as session:
        assert session.permanent
        assert 'user' in session
        assert session['user']['id'] == '12345'

def test_clean_logs(client, mock_env_vars, clean_db):
    """Test cleaning logs functionality"""
    # Create a test log entry
    with client.application.app_context():
        with client.session_transaction() as session:
            session['user'] = {
                'id': 12345,
                'first_name': 'Test',
                'username': os.getenv('ADMIN_USERNAME')  # Make the user an admin
            }
        
        # Add a test log
        log = UserLog(
            telegram_id='12345',
            first_name='Test',
            username='testuser',
            action='login'
        )
        db.session.add(log)
        db.session.commit()
        
        # Verify log exists
        assert UserLog.query.count() == 1
        
        # Try to clean logs
        response = client.post('/api/clean-logs')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['status'] == 'success'
        
        # Verify logs are cleaned
        assert UserLog.query.count() == 0
