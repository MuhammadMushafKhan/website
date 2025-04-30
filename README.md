# Message System Backend

This is an enhanced Flask backend application that provides user management and messaging features. It's designed to integrate with an existing frontend application that's hosted on Netlify.

## Features

- User registration and authentication
- Create, read, update, and delete messages
- Form validation and error handling
- RESTful API endpoints
- Secure password handling with hashing
- Cross-origin resource sharing (CORS) support for Netlify frontend

## API Endpoints

### Authentication

- `POST /register` - Register a new user
- `POST /login` - Login a user
- `GET/POST /logout` - Logout the current user

### Messages

- `POST /submit` - Submit a new message
- `GET /api/messages` - Get all messages for the current user
- `GET /api/messages/<id>` - Get a specific message
- `PUT /api/messages/<id>` - Update a message
- `DELETE /api/messages/<id>` - Delete a message

### User

- `GET /api/users/me` - Get current user information
- `GET /api/user/messages` - Get all messages for the current user

## Setting Up

### Requirements

- Python 3.6+
- Flask
- SQLite
- Flask-CORS

### Environment Variables

- `SESSION_SECRET` - Secret key for session management

### Running the Application

1. Install dependencies:
