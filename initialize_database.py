# -*- coding: gbk -*-# 
import sqlite3
from werkzeug.security import generate_password_hash

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

    # ����˺�Ϊ "1"������Ϊ "1" ���û�
    hashed_password = generate_password_hash("1")
    cursor.execute("INSERT INTO users (username, password, public_key) VALUES (?, ?, ?)", ("1", hashed_password, ""))
    
    conn.commit()
    conn.close()

if __name__ == '__main__':
    init_db()
