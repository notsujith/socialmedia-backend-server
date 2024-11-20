## Backend Social Media Server

This project implements a **social platform database** designed to manage users, posts, likes, tags, and user relationships efficiently. The primary goal is to ensure robust data integrity and seamless interaction between entities through well-structured database schemas and relationships.

### Key Features:
- **User Management**: Secure storage of user information, hashed passwords, and account roles (e.g., moderators).
- **Post Management**: Support for user-generated content with timestamps and categorization via tags.
- **Follow Relationships**: Users can follow and unfollow others with cascading updates and deletions for relational integrity.
- **Likes Tracking**: Keeps track of which users like which posts, ensuring unique likes per user per post.
- **Password History**: Stores historical hashed passwords for added security and policy compliance.

### Database Schema:
The schema includes the following tables:
- **Users**: Central table with unique usernames and email addresses.
- **Passwords**: Tracks password history for enhanced security.
- **Posts**: Stores user-generated content with metadata.
- **Tags**: Categorizes posts for discoverability.
- **Follows**: Manages "follow" relationships between users.
- **Likes**: Tracks user interactions with posts.

Refer to the [Database Schema PDF](Database-schema-project2.pdf) for detailed table definitions and relationships.

---

### Setup Instructions

1. Clone the repository:
   ```bash
   git clone <repository-url>
   ```
2. Set up the database using the provided SQL file:
   ```bash
   sqlite3 project2.db < project2.sql
   ```
3. Install dependencies for the application:
   ```bash
   pip install -r requirements.txt
   ```
4. Run the Python application:
   ```bash
   python app.py
   ```

### Security Key

Ensure the security key (from `key.txt`) is securely stored for application-level encryption.

### Dependencies

- Python 3.x
- SQLite
- Flask (if used in `app.py`)

---
