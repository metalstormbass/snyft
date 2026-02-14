"""
User service for managing user data
"""
from typing import List, Dict, Optional


class UserService:
    """Service class for user operations"""

    def __init__(self):
        self.users = [
            {'id': 1, 'name': 'John Doe', 'email': 'john@example.com'},
            {'id': 2, 'name': 'Jane Smith', 'email': 'jane@example.com'},
        ]

    def get_all_users(self) -> List[Dict]:
        """Get all users"""
        return self.users

    def get_user(self, user_id: int) -> Optional[Dict]:
        """Get a specific user by ID"""
        for user in self.users:
            if user['id'] == user_id:
                return user
        return None

    def add_user(self, name: str, email: str) -> Dict:
        """Add a new user"""
        user_id = max([u['id'] for u in self.users], default=0) + 1
        new_user = {'id': user_id, 'name': name, 'email': email}
        self.users.append(new_user)
        return new_user

    def update_user(self, user_id: int, name: str = None, email: str = None) -> Optional[Dict]:
        """Update an existing user"""
        user = self.get_user(user_id)
        if user:
            if name:
                user['name'] = name
            if email:
                user['email'] = email
            return user
        return None

    def delete_user(self, user_id: int) -> bool:
        """Delete a user"""
        user = self.get_user(user_id)
        if user:
            self.users.remove(user)
            return True
        return False
