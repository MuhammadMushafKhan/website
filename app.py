import os
import sqlite3
import logging
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS
from functools import wraps
from helpers import validate_email, validate_message, validate_username, validate_password
from forms import MessageForm, RegisterForm, LoginForm

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "dev_secret_key")  # Use environment variable with fallback
CORS(app)  # Allow cross-origin requests from the Netlify frontend

# Database setup
def get_db_connection():
    """Create and return a database connection"""
    conn = sqlite3.connect('form_data.db')
    conn.row_factory = sqlite3.Row  # This enables column access by name
    return conn

def init_db():
    """Initialize the database with required tables"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Create messages table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            message TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            user_id INTEGER
        )
    ''')
    
    # Create users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (  
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT UNIQUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    conn.commit()
    conn.close()

# Initialize the database
init_db()

# Authentication middleware
def login_required(f):
    """Decorator to ensure user is logged in before accessing certain routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.route('/')
def home():
    """Render the home page"""
    return render_template('index.html')

@app.route('/dashboard')
@login_required
def dashboard():
    """Render the dashboard page for logged-in users"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Get user information
    cursor.execute('SELECT id, username, email FROM users WHERE id = ?', (session['user_id'],))
    user = cursor.fetchone()
    
    # Get user's messages
    cursor.execute('SELECT id, name, email, message, created_at FROM messages WHERE user_id = ?', 
                  (session['user_id'],))
    messages = cursor.fetchall()
    
    conn.close()
    
    return render_template('dashboard.html', user=user, messages=messages)

@app.route('/submit', methods=['POST'])
def submit_form():
    """Handle form submission for contact messages"""
    try:
        # Get form data
        form = MessageForm(request.form)
        
        if not form.validate():
            return jsonify({'error': 'Validation failed', 'details': form.errors}), 400
        
        name = form.name.data
        email = form.email.data
        message = form.message.data
        
        # Check if user is logged in
        user_id = session.get('user_id')
        
        # Database insertion
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('INSERT INTO messages (name, email, message, user_id) VALUES (?, ?, ?, ?)', 
                      (name, email, message, user_id))
        conn.commit()
        conn.close()
        
        return jsonify({'message': 'Form submitted successfully!'}), 201
    
    except Exception as e:
        logger.error(f"Error submitting form: {str(e)}")
        return jsonify({'error': 'An error occurred while submitting the form'}), 500

@app.route('/api/messages', methods=['GET'])
@login_required
def get_all_messages():
    """API endpoint to get all messages for the current user"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id, name, email, message, created_at 
            FROM messages 
            WHERE user_id = ?
            ORDER BY created_at DESC
        ''', (session['user_id'],))
        
        messages = cursor.fetchall()
        conn.close()
        
        # Convert to list of dictionaries
        message_list = []
        for msg in messages:
            message_list.append({
                'id': msg['id'],
                'name': msg['name'],
                'email': msg['email'],
                'message': msg['message'],
                'created_at': msg['created_at']
            })
        
        return jsonify({'messages': message_list}), 200
    
    except Exception as e:
        logger.error(f"Error fetching messages: {str(e)}")
        return jsonify({'error': 'An error occurred while fetching messages'}), 500

@app.route('/api/messages/<int:message_id>', methods=['GET'])
@login_required
def get_message(message_id):
    """API endpoint to get a specific message"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id, name, email, message, created_at 
            FROM messages 
            WHERE id = ? AND user_id = ?
        ''', (message_id, session['user_id']))
        
        message = cursor.fetchone()
        conn.close()
        
        if not message:
            return jsonify({'error': 'Message not found or unauthorized'}), 404
        
        return jsonify({
            'id': message['id'],
            'name': message['name'],
            'email': message['email'],
            'message': message['message'],
            'created_at': message['created_at']
        }), 200
    
    except Exception as e:
        logger.error(f"Error fetching message: {str(e)}")
        return jsonify({'error': 'An error occurred while fetching the message'}), 500

@app.route('/api/messages/<int:message_id>', methods=['PUT'])
@login_required
def update_message(message_id):
    """API endpoint to update a specific message"""
    try:
        # Validate form data
        form = MessageForm(request.form)
        
        if not form.validate():
            return jsonify({'error': 'Validation failed', 'details': form.errors}), 400
        
        name = form.name.data
        email = form.email.data
        message = form.message.data
        
        # Check if message exists and belongs to the current user
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT user_id FROM messages WHERE id = ?', (message_id,))
        result = cursor.fetchone()
        
        if not result:
            conn.close()
            return jsonify({'error': 'Message not found'}), 404
            
        if result['user_id'] != session.get('user_id'):
            conn.close()
            return jsonify({'error': 'Unauthorized'}), 403
        
        # Update the message
        cursor.execute('''
            UPDATE messages 
            SET name = ?, email = ?, message = ? 
            WHERE id = ?
        ''', (name, email, message, message_id))
        
        conn.commit()
        conn.close()
        
        return jsonify({'message': 'Message updated successfully'}), 200
    
    except Exception as e:
        logger.error(f"Error updating message: {str(e)}")
        return jsonify({'error': 'An error occurred while updating the message'}), 500

@app.route('/api/messages/<int:message_id>', methods=['DELETE'])
@login_required
def delete_message(message_id):
    """API endpoint to delete a specific message"""
    try:
        # Check if message exists and belongs to the current user
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT user_id FROM messages WHERE id = ?', (message_id,))
        result = cursor.fetchone()
        
        if not result:
            conn.close()
            return jsonify({'error': 'Message not found'}), 404
            
        if result['user_id'] != session.get('user_id'):
            conn.close()
            return jsonify({'error': 'Unauthorized'}), 403
        
        # Delete the message
        cursor.execute('DELETE FROM messages WHERE id = ?', (message_id,))
        conn.commit()
        conn.close()
        
        return jsonify({'message': 'Message deleted successfully'}), 200
    
    except Exception as e:
        logger.error(f"Error deleting message: {str(e)}")
        return jsonify({'error': 'An error occurred while deleting the message'}), 500

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Handle user registration"""
    form = RegisterForm()
    
    if request.method == 'POST':
        try:
            # Process the API request if it's coming from the frontend
            if request.headers.get('Content-Type') == 'application/json':
                data = request.json
                username = data.get('username')
                password = data.get('password')
                email = data.get('email')
            else:
                # Process form data
                username = request.form.get('username')
                password = request.form.get('password')
                email = request.form.get('email')
            
            # Validate input
            if not validate_username(username):
                return jsonify({'error': 'Invalid username'}), 400
                
            if not validate_password(password):
                return jsonify({'error': 'Password must be at least 8 characters'}), 400
                
            if email and not validate_email(email):
                return jsonify({'error': 'Invalid email address'}), 400
            
            # Hash the password
            hashed_password = generate_password_hash(password)
            
            # Insert into database
            conn = get_db_connection()
            cursor = conn.cursor()
            
            try:
                cursor.execute(
                    'INSERT INTO users (username, password, email) VALUES (?, ?, ?)',
                    (username, hashed_password, email)
                )
                conn.commit()
                user_id = cursor.lastrowid
                
                # Set session
                session['user_id'] = user_id
                session['username'] = username
                
                if request.headers.get('Content-Type') == 'application/json':
                    return jsonify({'message': 'User registered successfully', 'username': username}), 201
                else:
                    flash('Registration successful! You are now logged in.', 'success')
                    return redirect(url_for('dashboard'))
                    
            except sqlite3.IntegrityError:
                conn.rollback()
                if request.headers.get('Content-Type') == 'application/json':
                    return jsonify({'error': 'Username or email already exists'}), 400
                else:
                    flash('Username or email already exists', 'danger')
            finally:
                conn.close()
                
        except Exception as e:
            logger.error(f"Error registering user: {str(e)}")
            if request.headers.get('Content-Type') == 'application/json':
                return jsonify({'error': 'An error occurred during registration'}), 500
            else:
                flash('An error occurred during registration', 'danger')
    
    # GET request - show registration form
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handle user login"""
    form = LoginForm()
    
    if request.method == 'POST':
        try:
            # Process the API request if it's coming from the frontend
            if request.headers.get('Content-Type') == 'application/json':
                data = request.json
                username = data.get('username')
                password = data.get('password')
            else:
                # Process form data
                username = request.form.get('username')
                password = request.form.get('password')
            
            # Validate input
            if not username or not password:
                if request.headers.get('Content-Type') == 'application/json':
                    return jsonify({'error': 'Username and password are required'}), 400
                else:
                    flash('Username and password are required', 'danger')
                    return render_template('login.html', form=form)
            
            # Check credentials
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute('SELECT id, username, password FROM users WHERE username = ?', (username,))
            user = cursor.fetchone()
            conn.close()
            
            if user and check_password_hash(user['password'], password):
                # Set session
                session['user_id'] = user['id']
                session['username'] = user['username']
                
                if request.headers.get('Content-Type') == 'application/json':
                    return jsonify({'message': 'Login successful', 'username': username}), 200
                else:
                    flash('Login successful!', 'success')
                    return redirect(url_for('dashboard'))
            else:
                if request.headers.get('Content-Type') == 'application/json':
                    return jsonify({'error': 'Invalid credentials'}), 401
                else:
                    flash('Invalid credentials', 'danger')
                    
        except Exception as e:
            logger.error(f"Error logging in: {str(e)}")
            if request.headers.get('Content-Type') == 'application/json':
                return jsonify({'error': 'An error occurred during login'}), 500
            else:
                flash('An error occurred during login', 'danger')
    
    # GET request - show login form
    return render_template('login.html', form=form)

@app.route('/logout', methods=['GET', 'POST'])
def logout():
    """Handle user logout"""
    # Clear the session
    session.pop('user_id', None)
    session.pop('username', None)
    
    if request.method == 'POST' and request.headers.get('Content-Type') == 'application/json':
        return jsonify({'message': 'Logged out successfully'}), 200
    else:
        flash('You have been logged out successfully', 'success')
        return redirect(url_for('home'))

@app.route('/api/users/me', methods=['GET'])
@login_required
def get_current_user():
    """API endpoint to get current user information"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT id, username, email FROM users WHERE id = ?', (session['user_id'],))
        user = cursor.fetchone()
        conn.close()
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        return jsonify({
            'id': user['id'],
            'username': user['username'],
            'email': user['email']
        }), 200
    
    except Exception as e:
        logger.error(f"Error getting user: {str(e)}")
        return jsonify({'error': 'An error occurred while fetching user data'}), 500

# This endpoint was removed to avoid conflict with /api/messages
# It provided similar functionality

@app.errorhandler(404)
def page_not_found(e):
    """Handle 404 errors"""
    return jsonify({'error': 'Not found'}), 404

@app.errorhandler(500)
def internal_server_error(e):
    """Handle 500 errors"""
    logger.error(f"Server error: {str(e)}")
    return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
