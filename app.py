from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import os
from datetime import datetime
from functools import wraps
from waitress import serve

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Database setup
def get_db_connection():
    conn = sqlite3.connect('todo.db')
    conn.row_factory = sqlite3.Row
    return conn

def create_tables():
    conn = get_db_connection()
    conn.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    conn.execute('''
    CREATE TABLE IF NOT EXISTS todos (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        description TEXT,
        status TEXT DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
    ''')
    conn.commit()
    conn.close()

create_tables()

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login first', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return redirect(url_for('register'))
        
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        
        if user:
            flash('Username already exists', 'error')
            conn.close()
            return redirect(url_for('register'))
        
        hashed_password = generate_password_hash(password)
        conn.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
        conn.commit()
        conn.close()
        
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'error')
    
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    conn = get_db_connection()
    todos = conn.execute('SELECT * FROM todos WHERE user_id = ? ORDER BY created_at DESC', (session['user_id'],)).fetchall()
    conn.close()
    return render_template('dashboard.html', todos=todos)

@app.route('/add_todo', methods=['POST'])
@login_required
def add_todo():
    title = request.form['title']
    description = request.form['description']
    
    conn = get_db_connection()
    conn.execute('INSERT INTO todos (user_id, title, description) VALUES (?, ?, ?)', 
                (session['user_id'], title, description))
    conn.commit()
    conn.close()
    
    flash('Todo added successfully!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/update_todo/<int:todo_id>', methods=['POST'])
@login_required
def update_todo(todo_id):
    new_status = request.form['status']
    
    conn = get_db_connection()
    # Verify the todo belongs to the current user
    todo = conn.execute('SELECT * FROM todos WHERE id = ? AND user_id = ?', (todo_id, session['user_id'])).fetchone()
    
    if todo:
        conn.execute('UPDATE todos SET status = ? WHERE id = ?', (new_status, todo_id))
        conn.commit()
        flash('Todo updated successfully!', 'success')
    else:
        flash('Todo not found or unauthorized', 'error')
    
    conn.close()
    return redirect(url_for('dashboard'))

@app.route('/delete_todo/<int:todo_id>')
@login_required
def delete_todo(todo_id):
    conn = get_db_connection()
    # Verify the todo belongs to the current user
    todo = conn.execute('SELECT * FROM todos WHERE id = ? AND user_id = ?', (todo_id, session['user_id'])).fetchone()
    
    if todo:
        conn.execute('DELETE FROM todos WHERE id = ?', (todo_id,))
        conn.commit()
        flash('Todo deleted successfully!', 'success')
    else:
        flash('Todo not found or unauthorized', 'error')
    
    conn.close()
    return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully', 'success')
    return redirect(url_for('login'))

@app.after_request
def add_header(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

if __name__ == '__main__':
    serve(app, host="0.0.0.0", port=9000)