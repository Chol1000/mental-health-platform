from extensions import db, bcrypt

class User(db.Model):
    __tablename__ = "users"  # Explicitly define the table name

    id = db.Column(db.Integer, primary_key=True)  # Unique ID for each user
    first_name = db.Column(db.String(50), nullable=False)  # First name of the user
    last_name = db.Column(db.String(50), nullable=False)  # Last name of the user
    email = db.Column(db.String(120), unique=True, nullable=False)  # Email (must be unique)
    password_hash = db.Column(db.String(128), nullable=False)  # Hashed password

    def set_password(self, password):
        """Hashes a password and stores it in the database."""
        self.password_hash = bcrypt.generate_password_hash(password).decode("utf-8")

    def check_password(self, password):
        """Verifies if the provided password matches the stored hash."""
        return bcrypt.check_password_hash(self.password_hash, password)
