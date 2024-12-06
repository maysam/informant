from datetime import datetime
from datetime import timezone as tz
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class UserLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    telegram_id = db.Column(db.String(32), nullable=False)
    first_name = db.Column(db.String(64))
    username = db.Column(db.String(64))
    action = db.Column(db.String(16), nullable=False)  # 'login' or 'logout'
    timestamp = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(tz.utc))

    def to_dict(self):
        return {
            'id': self.id,
            'telegram_id': self.telegram_id,
            'first_name': self.first_name,
            'username': self.username,
            'action': self.action,
            'timestamp': self.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')
        }
