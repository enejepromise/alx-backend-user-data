#!/usr/bin/env python3
"""
Flask App module
"""
from flask import Flask, jsonify, request, abort, redirect, url_for
from auth import Auth


app = Flask(__name__)
AUTH = Auth()


@app.route('/', strict_slashes=False)
def home():
    """Welcome"""
    return jsonify({"message": "Bienvenue"})


@app.route('/users', strict_slashes=False, methods=['POST'])
def users():
    """Handle user authentication and registration
    """
    email = request.form.get('email')
    password = request.form.get('password')

    try:
        AUTH.register_user(email, password)
        return jsonify({"email": email, "message": "user created"})

    except ValueError:
        return jsonify({"message": "email already registered"}), 400


@app.route('/profile', strict_slashes=False)
def profile():
    """Retrieve a user via session id"""
    sess_id = request.cookies.get('session_id')
    if sess_id is None:
        abort(403)

    user = AUTH.get_user_from_session_id(sess_id)

    if not user:
        abort(403)

    return jsonify({"email": user.email})


@app.route('/reset_password', strict_slashes=False, methods=['POST'])
def get_reset_password_token():
    email = request.form.get("email")

    if not email:
        abort(403)

    try:
        reset_token = AUTH.get_reset_password_token(email)
        return jsonify({"email": email, "reset_token": reset_token})
    except ValueError:
        abort(403)


@app.route('/reset_password', strict_slashes=False, methods=['PUT'])
def update_password():
    """updates a user's password"""
    email = request.form.get("email")
    new_password = request.form.get("new_password")
    reset_token = request.form.get("reset_token")

    if not email or not new_password or not reset_token:
        abort(400, description="Missing required fields")

    try:
        AUTH.update_password(reset_token, new_password)
        return jsonify({"email": email, "message": "Password updated"})
    except ValueError:
        abort(403)


@app.route('/sessions', strict_slashes=False, methods=['POST'])
def login():
    """Handles user's logins
    """
    email = request.form.get('email')
    password = request.form.get('password')

    if AUTH.valid_login(email, password):
        sess_id = AUTH.create_session(email)
        response = jsonify({"email": email, "message": "logged in"})
        response.set_cookie("session_id", sess_id)

        return response
    else:
        abort(401)


@app.route('/sessions', strict_slashes=False, methods=['DELETE'])
def logout():
    """Handles user's logout"""
    sess_id = request.cookies.get("session_id")
    user = AUTH.get_user_from_session_id(sess_id)

    if not user:
        abort(403)

    AUTH.destroy_session(user.id)

    return redirect(url_for('home'))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
