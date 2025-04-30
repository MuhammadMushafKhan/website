# This file would normally contain SQLAlchemy models
# but since we're using SQLite directly, we'll define our schemas here

class UserSchema:
    """Schema for User table"""
    id = "INTEGER PRIMARY KEY"
    username = "TEXT UNIQUE NOT NULL"
    password = "TEXT NOT NULL"
    email = "TEXT UNIQUE"
    created_at = "TIMESTAMP DEFAULT CURRENT_TIMESTAMP"
    
    @staticmethod
    def create_table_sql():
        return """
        CREATE TABLE IF NOT EXISTS users (  
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT UNIQUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """

class MessageSchema:
    """Schema for Message table"""
    id = "INTEGER PRIMARY KEY"
    name = "TEXT NOT NULL"
    email = "TEXT NOT NULL"
    message = "TEXT NOT NULL"
    created_at = "TIMESTAMP DEFAULT CURRENT_TIMESTAMP"
    user_id = "INTEGER"
    
    @staticmethod
    def create_table_sql():
        return """
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            message TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            user_id INTEGER
        )
        """
