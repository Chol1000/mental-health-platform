from flask import jsonify, request
from extensions import db, bcrypt
from sqlalchemy import text

def register_user():
    data = request.form

    # Extract fields
    first_name = data.get("first_name")
    last_name = data.get("last_name")
    email = data.get("email")
    password = data.get("password")

    # Validate input
    if not all([first_name, last_name, email, password]):
        return jsonify({"message": "All fields are required"}), 400

    # Check if user already exists
    with db.engine.connect() as connection:
        result = connection.execute(text("SELECT * FROM users WHERE email = :email"), {"email": email})
        if result.fetchone():
            return jsonify({"message": "User already exists"}), 409

    # Hash the password
    password_hash = bcrypt.generate_password_hash(password).decode("utf-8")

    # Insert the user into the database
    with db.engine.connect() as connection:
        connection.execute(text('''
            INSERT INTO users (first_name, last_name, email, password_hash)
            VALUES (:first_name, :last_name, :email, :password_hash)
        '''), {
            "first_name": first_name,
            "last_name": last_name,
            "email": email,
            "password_hash": password_hash
        })

    return jsonify({"message": "User registered successfully"}), 201
