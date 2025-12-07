// MongoDB Initialization Script for Auth Service
// Creates the authdb database and sets up initial user

// Switch to authdb database
db = db.getSiblingDB('authdb');

// Create application user with readWrite permissions
db.createUser({
    user: 'authuser',
    pwd: 'authpass123',
    roles: [
        {
            role: 'readWrite',
            db: 'authdb'
        }
    ]
});

// Create indexes for users collection
db.createCollection('users');
db.users.createIndex({ "email": 1 }, { unique: true });
db.users.createIndex({ "country": 1 });
db.users.createIndex({ "status": 1 });
db.users.createIndex({ "country": 1, "status": 1 });
db.users.createIndex({ "activation_token": 1 }, { sparse: true });
db.users.createIndex({ "password_reset_token": 1 }, { sparse: true });

// Create indexes for refresh_tokens collection
db.createCollection('refresh_tokens');
db.refresh_tokens.createIndex({ "token": 1 }, { unique: true });
db.refresh_tokens.createIndex({ "user_id": 1 });
db.refresh_tokens.createIndex({ "expires_at": 1 }, { expireAfterSeconds: 0 });

print('Auth Service MongoDB initialization complete!');
