from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from sqlalchemy import inspect
import re
import os
from datetime import datetime, timedelta, timezone
from sqlalchemy import func
import logging
from openai import OpenAI
from dotenv import load_dotenv
from pathlib import Path
import traceback

# =============================================
# INITIAL SETUP
# =============================================

# Initialize logging first
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# =============================================
# ENHANCED ENVIRONMENT VARIABLE LOADING
# =============================================

def load_environment_vars():
    """Robust environment variable loader with multiple fallback locations"""
    possible_paths = [
        Path('.env'),  # Current directory
        Path(r"C:\Users\LENOVO\OneDrive\Desktop\Mental-heath-platform") / '.env',
        Path.home() / '.env',
    ]
    
    loaded = False
    for env_path in possible_paths:
        try:
            if env_path.exists():
                load_dotenv(env_path, override=True)
                logger.info(f"✅ Successfully loaded .env from: {env_path}")
                loaded = True
                break
            else:
                logger.debug(f"⚠️ .env not found at: {env_path}")
        except Exception as e:
            logger.warning(f"❌ Failed to load .env from {env_path}: {str(e)}")
    
    if not loaded:
        logger.warning("🚨 No valid .env file found in any standard location")
    
    # Debug output
    logger.debug("\n=== ENVIRONMENT DEBUG ===")
    logger.debug(f"Current directory: {os.getcwd()}")
    logger.debug(f"OPENAI_API_KEY exists: {'YES' if os.getenv('OPENAI_API_KEY') else 'NO'}")
    
    if os.getenv('OPENAI_API_KEY'):
        key = os.getenv('OPENAI_API_KEY')
        logger.debug(f"Key length: {len(key)}")
        logger.debug(f"Key starts with: {key[:7]}...")
    
    logger.debug("=======================\n")

# Load environment variables
load_environment_vars()

# =============================================
# FLASK APPLICATION SETUP
# =============================================

app = Flask(__name__)
CORS(app)

# =============================================
# OPENAI CLIENT INITIALIZATION
# =============================================

def initialize_openai():
    """Initialize OpenAI client without validation checks or verification"""
    openai_api_key = os.getenv("OPENAI_API_KEY")
    
    if not openai_api_key:
        logger.warning("No OpenAI API key found in environment variables")
        return None
        
    try:
        # Create client with the provided key
        client = OpenAI(api_key=openai_api_key.strip())
        logger.info("OpenAI client initialized")
        return client
        
    except Exception as e:
        logger.error(f"OpenAI initialization failed: {str(e)}")
        return None

openai_client = initialize_openai()

# =============================================
# DATABASE CONFIGURATION
# =============================================

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_DIR = os.path.join(BASE_DIR, 'instance')
DB_PATH = os.path.join(DB_DIR, 'users.db')
os.makedirs(DB_DIR, exist_ok=True)

app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{DB_PATH}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# =============================================
# ENHANCED MENTAL HEALTH SUPPORT SYSTEM
# =============================================

# Expanded emotional vocabulary and support prompts
VALID_MOODS = [
    # Core Negative Emotions
    "Sad", "Depressed", "Heartbroken", "Gloomy",
    "Anxious", "Panicked", "Worried", "Nervous",
    "Angry", "Furious", "Irritated", "Resentful",
    "Stressed", "Overwhelmed", "Burdened", "Pressured",
    "Lonely", "Isolated", "Abandoned", "Disconnected",
    
    # Complex Negative States
    "Confused", "Disoriented", "Uncertain", "Lost",
    "Numb", "Empty", "Detached", "Disassociated",
    "Ashamed", "Guilty", "Embarrassed", "Humiliated",
    "Hopeless", "Despairing", "Defeated", "Powerless",
    
    # Neutral/Mixed States
    "Neutral", "Indifferent", "Apathetic", "Balanced",
    "Reflective", "Contemplative", "Thoughtful", "Pensive",
    "Tired", "Exhausted", "Drained", "Fatigued",
    
    # Positive States
    "Happy", "Joyful", "Content", "Cheerful",
    "Excited", "Enthusiastic", "Eager", "Energized",
    "Peaceful", "Calm", "Serene", "Tranquil",
    "Grateful", "Thankful", "Appreciative", "Blessed",
    "Hopeful", "Optimistic", "Encouraged", "Confident",
    
    # Special Cases
    "Unknown", "Mixed", "Conflicted", "Unsure"
]

# Mood intensity values (1-5 scale)
MOOD_VALUES = {
    # Negative emotions (1-3)
    **{mood: 1 for mood in ["Sad", "Depressed", "Heartbroken", "Gloomy", 
                           "Anxious", "Panicked", "Hopeless", "Despairing"]},
    **{mood: 2 for mood in ["Angry", "Furious", "Stressed", "Overwhelmed",
                           "Lonely", "Isolated", "Ashamed", "Guilty"]},
    **{mood: 3 for mood in ["Confused", "Numb", "Tired", "Reflective",
                           "Neutral", "Indifferent"]},
    
    # Positive emotions (4-5)
    **{mood: 4 for mood in ["Happy", "Content", "Peaceful", "Calm"]},
    **{mood: 5 for mood in ["Excited", "Joyful", "Grateful", "Hopeful"]},
    
    # Special cases
    "Unknown": 3,
    "Mixed": 3,
    "Conflicted": 2,
    "Unsure": 3
}


# Database Models
class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    checkins = db.relationship('CheckIn', backref='user', cascade='all, delete-orphan')
    journal_entries = db.relationship('JournalEntry', backref='user', cascade='all, delete-orphan')
    metrics = db.relationship('ProgressMetric', backref='user', cascade='all, delete-orphan')
    feedback = db.relationship('Feedback', backref='user', cascade='all, delete-orphan')

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

    def to_dict(self):
        return {
            "id": self.id,
            "first_name": self.first_name,
            "last_name": self.last_name,
            "email": self.email,
            "created_at": self.created_at.isoformat() if self.created_at else None
        }

class CheckIn(db.Model):
    __tablename__ = "checkins"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    date = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    mood = db.Column(db.String(20), nullable=False)
    energy_level = db.Column(db.Integer)
    anxiety_level = db.Column(db.Integer)
    notes = db.Column(db.Text)
    
    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "date": self.date.isoformat() if self.date else None,
            "mood": self.mood,
            "energy_level": self.energy_level,
            "anxiety_level": self.anxiety_level,
            "notes": self.notes
        }

class JournalEntry(db.Model):
    __tablename__ = "journal_entries"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    date = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    mood = db.Column(db.String(20))
    is_private = db.Column(db.Boolean, default=True)
    
    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "date": self.date.isoformat() if self.date else None,
            "title": self.title,
            "content": self.content,
            "mood": self.mood,
            "is_private": self.is_private
        }

class ProgressMetric(db.Model):
    __tablename__ = "progress_metrics"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    date = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    metric_type = db.Column(db.String(50), nullable=False)
    value = db.Column(db.Float, nullable=False)
    
    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "date": self.date.isoformat() if self.date else None,
            "metric_type": self.metric_type,
            "value": self.value
        }

class Feedback(db.Model):
    __tablename__ = "feedback"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    emotion = db.Column(db.String(50), nullable=False)
    text = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    is_processed = db.Column(db.Boolean, default=False)
    
    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "emotion": self.emotion,
            "text": self.text,
            "created_at": self.created_at.isoformat(),
            "is_processed": self.is_processed
        }

def initialize_database():
    with app.app_context():
        db.create_all()
        inspector = db.inspect(db.engine)
        table_names = inspector.get_table_names()
        logger.info("Database tables initialized:")
        logger.info(f"- Users table: {'users' in table_names}")
        logger.info(f"- Checkins table: {'checkins' in table_names}")
        logger.info(f"- Journal entries table: {'journal_entries' in table_names}")
        logger.info(f"- Progress metrics table: {'progress_metrics' in table_names}")
        logger.info(f"- Feedback table: {'feedback' in table_names}")

initialize_database()


# Utility functions
def validate_password(password):
    if len(password) < 8:
        return False, "Password must be at least 8 characters"
    if not re.search("[a-z]", password):
        return False, "Password needs a lowercase letter"
    if not re.search("[A-Z]", password):
        return False, "Password needs an uppercase letter"
    if not re.search("[0-9]", password):
        return False, "Password needs a number"
    return True, ""


# Enhanced mental health support prompts
MENTAL_HEALTH_PROMPTS = {
    # Core Negative Feelings - More comprehensive support
    "Sad": "Respond to sadness with deep compassion. Offer multiple forms of support: listening, gentle suggestions, and validation. Keep responses natural and conversational.",
    "Anxious": "Provide anxiety support with understanding and practical techniques. Offer 2-3 options for calming strategies, and let the user guide what they need.",
    "Angry": "Help process anger in healthy ways. Suggest physical, creative, and reflective outlets. Keep tone calm but understanding.",
    "Stressed": "Offer personalized stress relief options - immediate techniques and longer-term strategies. Adapt to the user's specific situation.",
    
    # Complex States
    "Confused": "Help clarify confusion by breaking things down. Offer different perspectives and encourage exploration of feelings.",
    "Numb": "Suggest gentle, non-threatening ways to reconnect with emotions. Provide options for different comfort levels.",
    "Hopeless": "Offer hope without dismissing feelings. Share small, manageable steps forward and validate the difficulty.",
    
    # Positive Feelings
    "Happy": "Celebrate happiness with genuine interest. Ask questions to help savor the moment and reinforce positive feelings.",
    "Excited": "Share excitement while helping channel energy positively. Suggest ways to harness this productive energy.",
    "Grateful": "Deepen gratitude through reflection and sharing. Offer prompts to explore gratitude further.",
    
    # Special Cases
    "Unknown": """
    When feelings are unclear:
    1. Gently explore physical sensations and thoughts
    2. Offer possible emotion words without pressure
    3. Suggest simple activities to help identify feelings
    4. Maintain supportive, non-judgmental presence
    """,
    
    "Mixed": """
    For mixed emotions:
    1. Acknowledge the complexity
    2. Help untangle different feelings
    3. Validate that conflicting emotions are normal
    4. Address each feeling as needed
    """,
    
    "default": "Provide compassionate, natural responses. Offer support while following the user's lead in conversation."
}

# Comprehensive fallback responses with multiple options
FALLBACK_RESPONSES = {
    # Negative Feelings
    "Sad": [
        "I hear how hard this is for you. You might try:",
        "• Writing about what's hurting",
        "• Reaching out to someone who cares",
        "• Gentle movement like walking",
        "• Looking at comforting images",
        "What feels most possible right now?"
    ],
    
    "Anxious": [
        "Anxiety can feel overwhelming. Some options:",
        "• 5-4-3-2-1 grounding (notice 5 things you see, 4 you can touch, etc.)",
        "• Box breathing (inhale 4s, hold 4s, exhale 4s, hold 4s)",
        "• Splashing cold water on your face",
        "• Repeating a calming phrase",
        "Would any of these help?"
    ],
    
    "Angry": [
        "Anger needs healthy outlets. You could:",
        "• Punch a pillow or scream into one",
        "• Do vigorous exercise",
        "• Write an angry letter (then tear it up)",
        "• Use cold water on your face",
        "What usually helps you release anger?"
    ],
    
    # Positive Feelings
    "Happy": [
        "I'm glad you're feeling happy! To enjoy this:",
        "• Notice physical sensations of happiness",
        "• Share the feeling with someone",
        "• Do something playful",
        "• Take a mental picture of this moment",
        "What's making you feel happy right now?"
    ],
    
    # Special Cases
    "Unknown": [
        "Not knowing how you feel is okay. We can:",
        "• Explore physical sensations together",
        "• Try naming possible emotions",
        "• Use colors or images to describe feelings",
        "• Sit with the uncertainty for a bit",
        "What feels right to try?"
    ],
    
    "Mixed": [
        "Mixed feelings are completely normal. We can:",
        "• List out the different emotions",
        "• Give each feeling some attention",
        "• Find where they overlap in your body",
        "• Accept that multiple feelings can coexist",
        "How would you like to approach this?"
    ],
    
    "default": [
        "I'm here to support you. We can:",
        "• Talk through what you're experiencing",
        "• Try some coping strategies",
        "• Just sit with these feelings together",
        "• Find ways to express what's inside",
        "What feels most helpful right now?"
    ]
}

# Routes
@app.route("/register", methods=["POST"])
def register():
    try:
        if not request.is_json:
            return jsonify({"success": False, "message": "Request must be JSON"}), 400
            
        data = request.get_json()
        logger.debug(f"Registration attempt for email: {data.get('email')}")
        
        required = ["first_name", "last_name", "email", "password"]
        if not all(field in data for field in required):
            return jsonify({"success": False, "message": "All fields are required"}), 400

        if not re.match(r"[^@]+@[^@]+\.[^@]+", data["email"]):
            return jsonify({"success": False, "message": "Invalid email format"}), 400

        is_valid, msg = validate_password(data["password"])
        if not is_valid:
            return jsonify({"success": False, "message": msg}), 400

        if User.query.filter_by(email=data["email"]).first():
            return jsonify({"success": False, "message": "Email already registered"}), 409

        user = User(
            first_name=data["first_name"],
            last_name=data["last_name"],
            email=data["email"]
        )
        user.set_password(data["password"])
        db.session.add(user)
        db.session.commit()

        logger.info(f"New user registered: {user.email}")
        return jsonify({
            "success": True,
            "message": "Registration successful",
            "user": user.to_dict()
        }), 201

    except Exception as e:
        db.session.rollback()
        logger.error(f"Registration failed: {str(e)}")
        return jsonify({
            "success": False,
            "message": "Registration failed. Please try again."
        }), 500

@app.route("/login", methods=["POST"])
def login():
    try:
        if not request.is_json:
            return jsonify({"success": False, "message": "Request must be JSON"}), 400
            
        data = request.get_json()
        logger.debug(f"Login attempt for email: {data.get('email')}")
        
        if not all(field in data for field in ["email", "password"]):
            return jsonify({"success": False, "message": "Email and password are required"}), 400

        user = User.query.filter_by(email=data["email"]).first()
        if not user:
            logger.warning(f"Login failed - user not found: {data['email']}")
            return jsonify({"success": False, "message": "Invalid email or password"}), 401
            
        if not user.check_password(data["password"]):
            logger.warning(f"Login failed - incorrect password for: {data['email']}")
            return jsonify({"success": False, "message": "Invalid email or password"}), 401

        logger.info(f"User logged in: {user.email}")
        return jsonify({
            "success": True,
            "message": "Login successful",
            "user": user.to_dict()
        }), 200

    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        return jsonify({
            "success": False,
            "message": "Login failed. Please try again."
        }), 500

@app.route("/api/user/profile", methods=["PUT"])
def update_profile():
    try:
        data = request.get_json()
        logger.debug(f"Profile update request: {data}")
        
        required_fields = ["id", "current_password", "first_name", "last_name", "email"]
        if not all(field in data for field in required_fields):
            return jsonify({"success": False, "message": "All fields are required"}), 400

        user = db.session.get(User, data["id"])
        if not user:
            logger.warning(f"Profile update failed - user not found: {data['id']}")
            return jsonify({"success": False, "message": "User not found"}), 404
        
        if not user.check_password(data["current_password"]):
            logger.warning(f"Profile update failed - incorrect password for user: {user.email}")
            return jsonify({"success": False, "message": "Current password is incorrect"}), 401

        if user.email != data["email"] and User.query.filter_by(email=data["email"]).first():
            logger.warning(f"Profile update failed - email already in use: {data['email']}")
            return jsonify({"success": False, "message": "Email already in use"}), 409

        user.first_name = data["first_name"]
        user.last_name = data["last_name"]
        user.email = data["email"]

        if data.get("new_password"):
            is_valid, msg = validate_password(data["new_password"])
            if not is_valid:
                return jsonify({"success": False, "message": msg}), 400
            user.set_password(data["new_password"])

        db.session.commit()
        logger.info(f"Profile updated successfully for user: {user.email}")
        
        return jsonify({
            "success": True,
            "message": "Profile updated successfully",
            "user": user.to_dict()
        })

    except Exception as e:
        db.session.rollback()
        logger.error(f"Profile update error: {str(e)}")
        return jsonify({
            "success": False,
            "message": "An error occurred while updating profile"
        }), 500

@app.route("/debug/user/<int:user_id>", methods=["GET"])
def debug_user(user_id):
    try:
        user = db.session.get(User, user_id)
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        return jsonify({
            "id": user.id,
            "email": user.email,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "created_at": user.created_at.isoformat() if user.created_at else None
        })
    except Exception as e:
        logger.error(f"Debug error: {str(e)}")
        return jsonify({"error": str(e)}), 500
    
@app.route("/api/user/<int:user_id>", methods=["DELETE"])
def delete_account(user_id):
    try:
        user = db.session.get(User, user_id)
        if not user:
            logger.warning(f"Delete account failed - user not found: {user_id}")
            return jsonify({"success": False, "message": "User not found"}), 404
        
        db.session.delete(user)
        db.session.commit()
        logger.info(f"User account deleted: {user_id}")
        return jsonify({"success": True, "message": "Account deleted successfully"})

    except Exception as e:
        db.session.rollback()
        logger.error(f"Delete account error: {str(e)}")
        return jsonify({
            "success": False,
            "message": "Failed to delete account"
        }), 500

@app.route("/api/checkins", methods=["POST"])
def create_checkin():
    try:
        data = request.get_json()
        logger.debug(f"New check-in for user: {data.get('user_id')}")
        
        if not all(field in data for field in ["user_id", "mood"]):
            return jsonify({"success": False, "message": "User ID and mood are required"}), 400
            
        if data["mood"] not in VALID_MOODS:
            return jsonify({
                "success": False,
                "message": f"Invalid mood. Must be one of: {', '.join(VALID_MOODS)}"
            }), 400
            
        checkin = CheckIn(
            user_id=data["user_id"],
            mood=data["mood"],
            energy_level=data.get("energy_level"),
            anxiety_level=data.get("anxiety_level"),
            notes=data.get("notes", "")
        )
        
        db.session.add(checkin)
        
        metric = ProgressMetric(
            user_id=data["user_id"],
            metric_type="mood",
            value=MOOD_VALUES[data["mood"]]
        )
        db.session.add(metric)
        db.session.commit()
        
        logger.info(f"Check-in created for user: {data['user_id']}")
        return jsonify({
            "success": True,
            "message": "Check-in submitted successfully",
            "checkin": checkin.to_dict()
        }), 201
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Check-in creation error: {str(e)}")
        return jsonify({
            "success": False,
            "message": "An error occurred. Please try again."
        }), 500
    
@app.route("/api/journal", methods=["POST", "OPTIONS"])
def handle_journal():
    if request.method == "OPTIONS":
        return jsonify({"success": True}), 200
        
    try:
        data = request.get_json()
        logger.debug(f"New journal entry for user: {data.get('user_id')}")
        
        if not all(field in data for field in ["user_id", "title", "content"]):
            return jsonify({"success": False, "message": "User ID, title and content are required"}), 400
            
        entry = JournalEntry(
            user_id=data["user_id"],
            title=data["title"],
            content=data["content"],
            mood=data.get("mood"),
            is_private=data.get("is_private", True)
        )
        
        db.session.add(entry)
        db.session.commit()
        logger.info(f"Journal entry created for user: {data['user_id']}")
        
        return jsonify({
            "success": True,
            "message": "Journal entry created successfully",
            "entry": entry.to_dict()
        }), 201
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Journal entry creation error: {str(e)}")
        return jsonify({
            "success": False,
            "message": "Failed to create journal entry"
        }), 500

@app.route("/api/journal/<int:user_id>", methods=["GET"])
def get_journal_entries(user_id):
    try:
        entries = JournalEntry.query.filter_by(user_id=user_id)\
            .order_by(JournalEntry.date.desc()).all()
            
        logger.debug(f"Retrieved {len(entries)} journal entries for user: {user_id}")
        return jsonify({
            "success": True,
            "entries": [entry.to_dict() for entry in entries]
        })
        
    except Exception as e:
        logger.error(f"Journal entries retrieval error: {str(e)}")
        return jsonify({
            "success": False,
            "message": "Failed to fetch journal entries"
        }), 500

@app.route("/api/progress/<int:user_id>", methods=["GET"])
def get_progress(user_id):
    try:
        today = datetime.now(timezone.utc).date()
        today_metric = ProgressMetric.query.filter(
            ProgressMetric.user_id == user_id,
            func.date(ProgressMetric.date) == today
        ).first()
        
        time_range = request.args.get("time_range", "week")
        query = ProgressMetric.query.filter_by(user_id=user_id)
        
        if time_range == "week":
            start_date = datetime.now(timezone.utc) - timedelta(days=7)
        elif time_range == "month":
            start_date = datetime.now(timezone.utc) - timedelta(days=30)
        elif time_range == "year":
            start_date = datetime.now(timezone.utc) - timedelta(days=365)
        else:
            start_date = None
            
        if start_date:
            query = query.filter(ProgressMetric.date >= start_date)
            
        metrics = query.order_by(ProgressMetric.date.asc()).all()
        
        logger.debug(f"Retrieved progress data for user: {user_id}, time range: {time_range}")
        return jsonify({
            "success": True,
            "today": today_metric.to_dict() if today_metric else None,
            "historical": [m.to_dict() for m in metrics]
        })
        
    except Exception as e:
        logger.error(f"Progress data retrieval error: {str(e)}")
        return jsonify({
            "success": False,
            "message": "Failed to fetch progress data"
        }), 500

@app.route("/logout", methods=["POST"])
def logout():
    try:
        response = jsonify({
            "success": True,
            "message": "Logged out successfully"
        })
        response.set_cookie('session', '', expires=0)
        return response
        
    except Exception as e:
        return jsonify({
            "success": False,
            "message": "Logout failed"
        }), 500
    
@app.route("/api/feedback", methods=["POST"])
def submit_feedback():
    try:
        data = request.get_json()
        logger.debug(f"New feedback from user: {data.get('user_id')}")
        
        if not all(field in data for field in ["user_id", "emotion", "text"]):
            return jsonify({"success": False, "message": "User ID, emotion and text are required"}), 400
            
        if data["emotion"].lower() not in [m.lower() for m in VALID_MOODS]:
            return jsonify({"success": False, "message": "Invalid emotion"}), 400
            
        feedback = Feedback(
            user_id=data["user_id"],
            emotion=data["emotion"].capitalize(),
            text=data["text"]
        )
        
        db.session.add(feedback)
        db.session.commit()
        
        return jsonify({
            "success": True,
            "message": "Feedback submitted successfully",
            "feedback": feedback.to_dict()
        }), 201
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Feedback submission error: {str(e)}")
        return jsonify({
            "success": False,
            "message": "Failed to submit feedback"
        }), 500
    

# =============================================
# ENHANCED CHAT ENDPOINT WITH EMOTION SUPPORT
# =============================================

@app.route("/api/chat", methods=["POST"])
def chat_with_ai():
    try:
        data = request.get_json()
        logger.debug(f"AI chat request from user: {data.get('user_id')}")
        
        # Validate required fields
        if not all(field in data for field in ["user_id", "message"]):
            return jsonify({"success": False, "message": "User ID and message are required"}), 400

        # Get emotion or use default
        emotion = data.get("emotion", "default")
        if emotion not in VALID_MOODS:
            emotion = "Unknown"  # Handle unrecognized emotions
            
        # Prepare system prompt based on emotion
        system_prompt = MENTAL_HEALTH_PROMPTS.get(emotion, MENTAL_HEALTH_PROMPTS["default"])
        
        # Add conversation context
        messages = [{"role": "system", "content": system_prompt}]
        
        # Include conversation history if available
        conversation_history = data.get("conversation", [])
        messages.extend(conversation_history[-6:])  # Last 3 exchanges
        
        # Add current message
        messages.append({"role": "user", "content": data["message"]})
        
        # Try OpenAI API first
        if os.getenv("OPENAI_API_KEY"):
            try:
                client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
                
                response = client.chat.completions.create(
                    model="gpt-3.5-turbo",
                    messages=messages,
                    temperature=0.9,  # More creative responses
                    max_tokens=250,   # Longer responses
                    timeout=15
                )
                
                if response.choices and response.choices[0].message:
                    reply = response.choices[0].message.content.strip()
                    return jsonify({
                        "success": True,
                        "reply": reply,
                        "is_fallback": False
                    })
                    
            except Exception as api_error:
                logger.warning(f"API attempt failed: {str(api_error)}")
        
        # Fallback to predefined responses
        fallback = FALLBACK_RESPONSES.get(emotion, FALLBACK_RESPONSES["default"])
        return jsonify({
            "success": True,
            "reply": "\n".join(fallback),
            "is_fallback": True
        })
        
    except Exception as e:
        logger.error(f"Chat error: {str(e)}\n{traceback.format_exc()}")
        return jsonify({
            "success": False,
            "message": "Chat processing failed",
            "error": str(e) if app.debug else None
        }), 500

if __name__ == "__main__":
    # Final verification
    logger.debug("\n=== STARTUP VERIFICATION ===")
    logger.debug(f"OpenAI Status: {'✅ Ready' if openai_client else '❌ Not available'}")
    logger.debug(f"Database Path: {DB_PATH}")
    logger.debug("===========================")
    
    app.run(debug=True, port=5000)
