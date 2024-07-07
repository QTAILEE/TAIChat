# -*- coding: gbk -*-
# -*- coding: gbk -*-
from flask import Flask, render_template, request, jsonify, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'
DATABASE = 'database.db'

def init_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            public_key TEXT NOT NULL
        )                
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id TEXT NOT NULL,
            receiver_id TEXT NOT NULL,
            content TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS friends (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            friend_id INTEGER NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (friend_id) REFERENCES users(id)
        )
    ''')
    conn.commit()
    conn.close()

@app.route('/', methods=['GET'])
def home():
    print("GET / - Session:", session)
    if 'username' in session:
        return redirect(url_for('index_page'))
    else:
        return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html')
    elif request.method == 'POST':
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')

        if not username or not password:
            return 'Username and password are required', 400

        hashed_password = generate_password_hash(password)
        
        try:
            conn = sqlite3.connect(DATABASE)
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (username, password, public_key) VALUES (?, ?, ?)", (username, hashed_password, ""))
            conn.commit()
            conn.close()
            return jsonify({'message': 'Registration successful'}), 200
        except Exception as e:
            return f'Registration failed: {str(e)}', 500

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        print("GET /login - Session:", session)
        if 'username' in session:
            return redirect(url_for('index_page'))
        return render_template('login.html')
    
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'error': 'Username and password are required'}), 400

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, password, public_key FROM users WHERE username=?", (username,))
    user = cursor.fetchone()
    conn.close()

    if not user:
        return jsonify({'error': 'User not found'}), 401

    user_id, db_username, hashed_password, public_key = user
    if check_password_hash(hashed_password, password):
        session['username'] = username
        response = jsonify({'message': 'Login successful', 'username': username})
        response.set_cookie('username', username, max_age=60*60*24*7, httponly=True, samesite='Lax')
        print("Login successful - Session:", session)
        return response
    else:
        return jsonify({'error': 'Incorrect password'}), 401

@app.route('/index', methods=['GET'])
def index_page():
    print("GET /index - Session:", session)
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('index.html', username=session['username'])

@app.route('/logout')
def logout():
    print("GET /logout - Session before clear:", session)
    session.pop('username', None)
    response = redirect(url_for('login'))
    response.set_cookie('username', '', expires=0, httponly=True, samesite='Lax', path='/')
    print("GET /logout - Session after clear:", session)
    return response


@app.route('/get-users', methods=['GET'])
def get_users():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("SELECT username FROM users")
    users = cursor.fetchall()
    conn.close()
    return jsonify({'users': [user[0] for user in users]})

@app.route('/get-friends', methods=['GET'])
def get_friends():
    if 'username' not in session:
        return jsonify({'error': 'Not logged in'}), 401

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE username=?", (session['username'],))
    user_id = cursor.fetchone()[0]

    cursor.execute("""
        SELECT u.username FROM friends f
        JOIN users u ON f.friend_id = u.id
        WHERE f.user_id = ?
    """, (user_id,))
    friends = cursor.fetchall()
    conn.close()

    return jsonify({'friends': [friend[0] for friend in friends]})


@app.route('/send_message', methods=['POST'])
def send_message():
    data = request.get_json()
    sender_id = data.get('sender_id')
    receiver_id = data.get('receiver_id')
    content = data.get('content')

    if not sender_id or not receiver_id or not content:
        return jsonify({'error': 'Sender ID, receiver ID, and message content are required'}), 400

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO messages (sender_id, receiver_id, content) VALUES (?, ?, ?)", (sender_id, receiver_id, content))
    conn.commit()
    conn.close()

    return jsonify({'message': 'Message sent successfully'}), 200


@app.route('/get_messages', methods=['POST'])
def get_messages():
    data = request.get_json()
    sender_id = data.get('sender_id')
    receiver_id = data.get('receiver_id')

    if not sender_id or not receiver_id:
        return jsonify({'error': 'Sender ID and receiver ID are required'}), 400

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT sender_id, receiver_id, content, strftime('%Y-%m-%dT%H:%M:%SZ', timestamp) as timestamp
        FROM messages
        WHERE (sender_id=? AND receiver_id=?) OR (sender_id=? AND receiver_id=?)
        ORDER BY timestamp
    """, (sender_id, receiver_id, receiver_id, sender_id))
    messages = cursor.fetchall()
    conn.close()

    formatted_messages = [{'sender': sender, 'receiver': receiver, 'content': content, 'timestamp': timestamp} for sender, receiver, content, timestamp in messages]

    return jsonify({'messages': formatted_messages}), 200


@app.route('/add_friend', methods=['POST'])
def add_friend():
    data = request.get_json()
    username = data.get('username')
    friend_username = data.get('friend')

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    # Get user id
    cursor.execute("SELECT id FROM users WHERE username=?", (username,))
    user = cursor.fetchone()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    user_id = user[0]

    # Get friend id
    cursor.execute("SELECT id FROM users WHERE username=?", (friend_username,))
    friend = cursor.fetchone()
    if not friend:
        return jsonify({'error': 'Friend not found'}), 404
    friend_id = friend[0]

    # Check if already friends
    cursor.execute("SELECT * FROM friends WHERE user_id=? AND friend_id=?", (user_id, friend_id))
    existing_friendship = cursor.fetchone()
    if existing_friendship:
        return jsonify({'error': 'Already friends'}), 400

    # Add friend
    cursor.execute("INSERT INTO friends (user_id, friend_id) VALUES (?, ?)", (user_id, friend_id))
    conn.commit()
    conn.close()

    return jsonify({'message': 'Friend added successfully'}), 200


if __name__ == '__main__':
    init_db()
    app.run(debug=True)
