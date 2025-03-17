from flask import Flask, request, jsonify
from extensions import db, bcrypt  # Import db and bcrypt from extensions
from sqlalchemy import text

app = Flask(__name__)

# Configuration
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Initialize extensions
db.init_app(app)
bcrypt.init_app(app)

# Create the `users` table using raw SQL
with app.app_context():
    with db.engine.connect() as connection:
        connection.execute(text('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                first_name TEXT NOT NULL,
                last_name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            );
        '''))

# Register Route
@app.route("/register", methods=["POST"])
def register():
    data = request.form
    first_name = data.get("first_name")
    last_name = data.get("last_name")
    email = data.get("email")
    password = data.get("password")

    # Validate input
    if not all([first_name, last_name, email, password]):
        return jsonify({"message": "All fields are required"}), 400

    # Hash the password
    password_hash = bcrypt.generate_password_hash(password).decode("utf-8")

    # Insert user into the database
    try:
        with db.engine.connect() as connection:
            connection.execute(
                text("""
                    INSERT INTO users (first_name, last_name, email, password_hash)
                    VALUES (:first_name, :last_name, :email, :password_hash);
                """),
                {
                    "first_name": first_name,
                    "last_name": last_name,
                    "email": email,
                    "password_hash": password_hash,
                },
            )
        return jsonify({"message": "User registered successfully"}), 201
    except Exception as e:
        return jsonify({"message": "User already exists"}), 409

# Login Route
@app.route("/login", methods=["POST"])
def login():
    data = request.form
    email = data.get("email")
    password = data.get("password")

    # Validate input
    if not all([email, password]):
        return jsonify({"message": "Email and password are required"}), 400

    # Query the database for the user
    with db.engine.connect() as connection:
        result = connection.execute(
            text("SELECT * FROM users WHERE email = :email"),
            {"email": email},
        ).fetchone()

    # Check if user exists
    if not result:
        return jsonify({"message": "Invalid email or password"}), 401

    # Verify the password
    user_id, first_name, last_name, email, password_hash = result
    if not bcrypt.check_password_hash(password_hash, password):
        return jsonify({"message": "Invalid email or password"}), 401

    # Successful login
    return jsonify({"message": "Login successful", "user": {"id": user_id, "first_name": first_name, "last_name": last_name, "email": email}}), 200

if __name__ == "__main__":
    app.run(debug=True)
