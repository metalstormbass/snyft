"""
Main Flask application
"""
from flask import Flask, jsonify
from user_service import UserService

app = Flask(__name__)
user_service = UserService()


@app.route('/api/users', methods=['GET'])
def get_users():
    """Get all users"""
    users = user_service.get_all_users()
    return jsonify(users)


@app.route('/api/users/<int:user_id>', methods=['GET'])
def get_user(user_id):
    """Get a specific user by ID"""
    user = user_service.get_user(user_id)
    if user:
        return jsonify(user)
    return jsonify({'error': 'User not found'}), 404


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
