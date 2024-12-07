from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class UserLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    telegram_id = db.Column(db.Integer, nullable=False)
    first_name = db.Column(db.String(64), nullable=False)
    username = db.Column(db.String(64))
    action = db.Column(db.String(32), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'telegram_id': self.telegram_id,
            'first_name': self.first_name,
            'username': self.username,
            'action': self.action,
            'timestamp': self.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')
        }

class TelegramUser(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    telegram_id = db.Column(db.Integer, unique=True, nullable=False)
    username = db.Column(db.String(32), unique=True)
    first_name = db.Column(db.String(64), nullable=False)
    last_name = db.Column(db.String(64))
    photo_url = db.Column(db.String(255))
    auth_date = db.Column(db.Integer, nullable=False)
    hash = db.Column(db.String(64), nullable=False)
    can_send_messages = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def __repr__(self):
        return f'<User {self.username or self.first_name}>'

class Group(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    members = db.Column(db.Text, default='')  # Store members as comma-separated text

    def get_members(self):
        """Get list of members from the stored string"""
        if not self.members:
            return []
        return [member.strip() for member in str(self.members).split(',') if member.strip()]

    def add_member(self, member_name):
        """Add a new member to the group"""
        current_members = self.get_members()
        if member_name not in current_members:
            current_members.append(member_name)
            self.members = ','.join(current_members)

    def remove_member(self, member_name):
        """Remove a member from the group"""
        current_members = self.get_members()
        if member_name in current_members:
            current_members.remove(member_name)
            self.members = ','.join(current_members)

    def __repr__(self):
        return f'<Group {self.name}>'

# Remove the association table since we're using text-based members
# Association table for many-to-many relationship between users and groups
# group_member_association = db.Table('group_member_association',
#     db.Column('user_id', db.Integer, db.ForeignKey('telegram_user.id'), primary_key=True),
#     db.Column('group_id', db.Integer, db.ForeignKey('group.id'), primary_key=True)
# )
