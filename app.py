import base64
import hashlib
import hmac
import sqlite3
import os
import json
from flask import Flask, request

app = Flask(__name__)
db_name = "project2.db"
sql_file = "project2.sql"
db_flag = False


def create_db():
    global db_flag
    conn = sqlite3.connect(db_name)
    with open(sql_file, 'r') as sql_startup:
        init_db = sql_startup.read()

    cursor = conn.cursor()
    cursor.executescript(init_db)
    conn.commit()
    conn.close()
    db_flag = True
    return conn


def get_db():
    if not db_flag:
        create_db()
    conn = sqlite3.connect(db_name)
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA journal_mode = WAL;")
    return conn


def init_db():
    if not os.path.exists(db_name):
        conn = sqlite3.connect(db_name)
        with open(sql_file, 'r') as f:
            conn.executescript(f.read())
        conn.commit()
        conn.close()
    return "Initialized"


@app.route('/clear', methods=(['GET']))
def clear():
    os.remove(db_name) if os.path.exists(db_name) else None
    db_flag = False
    init_db()
    return "Cleared"


def validate_password(password, username, first_name, last_name, salt):
    complete_pass = password + salt
    encoded_pass = complete_pass.encode()
    hashed_pass = hashlib.sha256(encoded_pass).hexdigest()

    if len(password) < 8:
        return False
    if not any(char.isdigit() for char in password):
        return False
    if not any(char.isupper() for char in password):
        return False
    if not any(char.islower() for char in password):
        return False
    if username in password:
        return False
    if first_name in password:
        return False
    if last_name in password:
        return False

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT previous_hashed_pass FROM passwords WHERE user_name = ?;", (username,))
    result = cursor.fetchall()
    conn.commit()
    conn.close()

    for prev_pass in result:
        if hashed_pass == prev_pass[0]:
            return False

    return True


def check_email(email_address):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT email_address FROM users WHERE email_address = ?;", (email_address,))
    result = cursor.fetchall()
    conn.close()
    return len(result) > 0


def check_username(username):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?;", (username,))
    result = cursor.fetchall()
    conn.commit()
    conn.close()
    return len(result) > 0


@app.route('/create_user', methods=['POST'])
def create_user():
    first_name = request.form.get('first_name')
    last_name = request.form.get('last_name')
    email_address = request.form.get('email_address')
    password = request.form.get('password')
    username = request.form.get('username')
    salt = request.form.get('salt')
    moderator = 1 if request.form.get('moderator') == 'True' else 0

    if check_email(email_address):
        return json.dumps({'status': 3, 'pass_hash': 'NULL'})
    if check_username(username):
        return json.dumps({'status': 2, 'pass_hash': 'NULL'})
    if not validate_password(password, username, first_name, last_name, salt):
        return json.dumps({'status': 4, 'pass_hash': 'NULL'})

    conn = get_db()
    cursor = conn.cursor()
    complete_pass = password + salt
    encoded_pass = complete_pass.encode()
    hashed_pass = hashlib.sha256(encoded_pass).hexdigest()
    cursor.execute("INSERT INTO users VALUES (?, ?, ?, ?, ?, ?, ?);",
                   (first_name, last_name, username, email_address, hashed_pass, salt, moderator))
    cursor.execute("INSERT INTO passwords VALUES (?, ?);", (username, hashed_pass))
    conn.commit()
    conn.close()
    return json.dumps({'status': 1, 'pass_hash': hashed_pass})


def get_jwt(header, payload):
    with open("key.txt", "r") as key_file:
        key = key_file.read()
    key_bytes = key.encode('utf-8')

    encoded_header = header.encode('utf-8')
    encoded_payload = payload.encode('utf-8')

    encoded_header = base64.urlsafe_b64encode(encoded_header)
    encoded_payload = base64.urlsafe_b64encode(encoded_payload)

    signature = hmac.new(key_bytes, msg=encoded_header + b'.' + encoded_payload, digestmod=hashlib.sha256).hexdigest()

    jwt_token = encoded_header.decode('utf-8') + '.' + encoded_payload.decode('utf-8') + '.' + signature
    return jwt_token


def verify_jwt(jwt_token):
    with open("key.txt", "r") as key_file:
        key = key_file.read()
    key_bytes = key.encode('utf-8')

    encoded_header, encoded_payload, signature = jwt_token.split('.')
    encoded_header = encoded_header.encode('utf-8')
    encoded_payload = encoded_payload.encode('utf-8')

    new_signature = hmac.new(key_bytes, msg=encoded_header + b'.' + encoded_payload,
                             digestmod=hashlib.sha256).hexdigest()

    return new_signature == signature


@app.route('/login', methods=['POST'])
def user_login():
    username = request.form.get('username')
    password = request.form.get('password')
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT salt FROM users WHERE username = ?;", (username,))
    result = cursor.fetchall()
    conn.close()

    if not result:
        return json.dumps({'status': 0, 'jwt': 'NULL'})
    salt = result[0][0]
    complete_pass = password + salt
    encoded_pass = complete_pass.encode()
    hashed_pass = hashlib.sha256(encoded_pass).hexdigest()

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?;", (username,))
    result = cursor.fetchall()
    conn.close()

    if len(result) == 0:
        return json.dumps({'status': 0, 'jwt': 'NULL'})
    if result[0][4] == hashed_pass:
        header = json.dumps({"alg": "HS256", "typ": "JWT"})
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT moderator FROM users WHERE username = ?;", (username,))
        result = cursor.fetchone()
        conn.close()
        moderator_status = result[0]  
        if moderator_status == 1:
            payload = json.dumps({"username": username, "access": "True", "moderator": "True"})
        else:
            payload = json.dumps({"username": username, "access": "True"})

        jwt_token = get_jwt(header, payload)
        return json.dumps({'status': 1, 'jwt': jwt_token})
    else:
        return json.dumps({'status': 2, 'jwt': 'NULL'})


@app.route('/create_post', methods=['POST'])
def create_post():
    title = request.form.get('title')
    body = request.form.get('body')
    post_id = request.form.get('post_id')
    tags_param = request.form.get('tags')
    if tags_param:
        tags = json.loads(tags_param)
    else:
        tags = None

    jwt_token = request.headers['Authorization']
    if not verify_jwt(jwt_token):
        return json.dumps({'status': 2})
    else:
        encoded_header, encoded_payload, signature = jwt_token.split('.')
        decoded_payload = base64.urlsafe_b64decode(encoded_payload)
        payload = json.loads(decoded_payload.decode('utf-8'))
        current_username = payload.get('username')
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO posts (title, body, post_id, owner) VALUES (?, ?, ?, ?);",
                       (title, body, post_id, current_username))
        if tags != None:
            for tag in tags:
                cursor.execute("INSERT INTO tags VALUES(?, ?);", (post_id, tags[tag]))
        conn.commit()
        conn.close()
        return json.dumps({'status': 1})
    

@app.route('/update', methods=['POST'])
def update_user():
    username = request.form.get('username')
    new_username = request.form.get('new_username')
    password = request.form.get('password')
    new_password = request.form.get('new_password')
    jwt = request.form.get('jwt')

    try:
        header, payload, signature = jwt.split('.')
    except ValueError:
        return json.dumps({'status': 3})
    
    new_header = json.loads(base64.urlsafe_b64decode(header.encode()).decode())
    new_payload = json.loads(base64.urlsafe_b64decode(payload.encode()).decode())
    new_jwt = get_jwt(json.dumps(new_header), json.dumps(new_payload))

    if jwt != new_jwt:
        return json.dumps({'status': 3})

    conn = get_db()
    cursor = conn.cursor()

    if new_username:
        if check_username(new_username):
            return json.dumps({'status': 2})
        cursor.execute("UPDATE users SET username = ? WHERE username = ?;", (new_username, username))

        conn.commit()
        conn.close()
        return json.dumps({'status': 1})
    
    elif new_password:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT first_name, last_name, salt FROM users WHERE username = ?;", (username,))
        result = cursor.fetchall()
        conn.close()
        first_name = result[0][0]
        last_name = result[0][1]
        salt = result[0][2]

        if not validate_password(new_password, new_username, first_name, last_name, salt):
            return json.dumps({'status': 4})
        complete_pass = new_password + salt
        encoded_pass = complete_pass.encode()
        hashed_pass = hashlib.sha256(encoded_pass).hexdigest()
        cursor.execute("UPDATE users SET password = ? WHERE username = ?;", (hashed_pass, username))
        cursor.execute("PRAGMA foreign_keys = ON;")
        cursor.execute("UPDATE passwords SET previous_hashed_pass = ? WHERE user_name = ?;", (hashed_pass, username))
        conn.commit()
        conn.close()
        return json.dumps({'status': 1})


@app.route('/view_user', methods=['POST'])
def view_user():
    jwt = request.form.get('jwt')
    try:
        header, payload, signature = jwt.split('.')
    except ValueError:
        return json.dumps({'status': 2, 'data': 'NULL'})
    
    new_header = json.loads(base64.urlsafe_b64decode(header.encode()).decode())
    new_payload = json.loads(base64.urlsafe_b64decode(payload.encode()).decode())
    new_jwt = get_jwt(json.dumps(new_header), json.dumps(new_payload))

    if jwt != new_jwt:
        return json.dumps({'status': 2, 'data': 'NULL'})

    username = new_payload['username']
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT username, email_address, first_name, last_name FROM users WHERE username = ?;", (username,))

    result = cursor.fetchall()
    conn.commit()
    conn.close()
    data = {'username': result[0][0], 'email_address': result[0][1], 'first_name': result[0][2], 'last_name': result[0][3]}

    return json.dumps({'status': 1, 'data': data})


@app.route('/follow', methods=['POST'])
def follow_user():
    username = request.form.get('username')
    jwt = request.headers['Authorization']
    if not verify_jwt(jwt):
        return json.dumps({'status': 2})
    else:
        encoded_header, encoded_payload, signature = jwt.split('.')
        decoded_payload = base64.urlsafe_b64decode(encoded_payload)
        payload = json.loads(decoded_payload.decode('utf-8'))
        current_username = payload.get('username')
        if current_username == username:
            return json.dumps({'status': 2})
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT followed_username FROM follows WHERE follower_username = ? AND followed_username = ?;", (current_username, username))
        result = cursor.fetchall()
        if len(result) > 0:
            conn.close()
            return json.dumps({'status': 2})
        cursor.execute("INSERT INTO follows VALUES(?, ?);", (current_username, username))
        conn.commit()
        conn.close()
        return json.dumps({'status': 1})
    

@app.route('/like', methods=['POST'])
def like_post():
    post_id = request.form.get('post_id')
    jwt = request.headers['Authorization']
    if not verify_jwt(jwt):
        return json.dumps({'status': 2})
    else:
        encoded_header, encoded_payload, signature = jwt.split('.')
        decoded_payload = base64.urlsafe_b64decode(encoded_payload)
        payload = json.loads(decoded_payload.decode('utf-8'))
        current_username = payload.get('username')

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT owner FROM posts WHERE post_id = ?;", (post_id,))
        result = cursor.fetchone()
        if not result:
            conn.close()
            return json.dumps({'status': 2})
        post_owner = result[0]
        if current_username != post_owner:
            cursor.execute("SELECT COUNT(*) FROM follows WHERE follower_username = ? AND followed_username = ?;", (current_username, post_owner))
            result = cursor.fetchone()
            if result[0] == 0:
                conn.close()
                return json.dumps({'status': 2})
        try:
            cursor.execute("INSERT INTO likes VALUES(?, ?);", (post_id, current_username))
            conn.commit()
            conn.close()
            return json.dumps({'status': 1})
        except sqlite3.IntegrityError:
            conn.close()
            return json.dumps({'status': 2})
    

@app.route( '/view_post/<post_id>', methods=['GET'])
def view_post(post_id):
    jwt = request.headers['Authorization']
    if not verify_jwt(jwt):
        return json.dumps({'status': 2, 'data': 'NULL'})
    else:
        encoded_header, encoded_payload, signature = jwt.split('.')
        decoded_payload = base64.urlsafe_b64decode(encoded_payload)
        payload = json.loads(decoded_payload.decode('utf-8'))
        current_username = payload.get('username')

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT owner FROM posts WHERE post_id = ?;", (post_id,))
        result = cursor.fetchone()
        if not result:
            conn.close()
            return json.dumps({'status': 2, 'data': 'NULL'})
        post_owner = result[0]
        if current_username != post_owner:
            cursor.execute("SELECT * FROM follows WHERE follower_username = ? AND followed_username = ?", (current_username, post_owner))
            follows = cursor.fetchone()
            if not follows:
                conn.close()
                return json.dumps({'status': 2, 'data': 'NULL'})
        cursor.execute("SELECT title, body, owner FROM posts WHERE post_id = ?;", (post_id,))
        result = cursor.fetchone()
        if not result:
            conn.close()
            return json.dumps({'status': 2, 'data': 'NULL'})
        title, body, owner = result

        data = {}
        title_requested = request.args.get('title') == 'True'
        body_requested = request.args.get('body') == 'True'
        tags_requested = request.args.get('tags') == 'True'
        owner_requested = request.args.get('owner') == 'True'
        likes_requested = request.args.get('likes') == 'True'

        if title_requested:
            data['title'] = title
        if body_requested:
            data['body'] = body
        if owner_requested:
            data['owner'] = owner
        if tags_requested:
            cursor.execute("SELECT tags FROM tags WHERE post_id = ?;", (post_id,))
            tags = cursor.fetchall()
            data['tags'] = [tag[0] for tag in tags]
        if likes_requested:
            cursor.execute("SELECT COUNT(*) FROM likes WHERE post_id = ?;", (post_id,))
            likes = cursor.fetchone()
            data['likes'] = likes[0]
            
        conn.close()
        return json.dumps({'status': 1, 'data': data})
        

@app.route('/search', methods=['GET'])
def search_post():
    jwt = request.headers["Authorization"]
    feed = request.args.get("feed")
    tag = request.args.get("tag")
    encoded_header, encoded_payload, signature = jwt.split('.')
    decoded_payload = base64.urlsafe_b64decode(encoded_payload)
    payload = json.loads(decoded_payload.decode('utf-8'))
    current_username = payload.get('username')

    if feed:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT post_id, title, body, owner FROM posts WHERE OWNER IN (SELECT followed_username FROM follows WHERE follower_username = ?) ORDER BY created_at DESC, post_id DESC LIMIT 5;", (current_username,))
        result = cursor.fetchall()
        return_json = {}
        for i in range(len(result)):
            cursor.execute("SELECT tags FROM tags WHERE post_id = ?;", (result[i][0],))
            result_tags = cursor.fetchall()
            cursor.execute("SELECT COUNT(*) FROM likes WHERE post_id = ?;", (result[i][0],))
            likes = cursor.fetchone()
            return_json[str(result[i][0])] = {'title': result[i][1], 'body': result[i][2], 'owner': result[i][3], 'tags': [tag[0] for tag in result_tags], 'likes': likes[0]}
        conn.close()
        return json.dumps({'status': 1, 'data': return_json}, ensure_ascii=False)
    
    if tag:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT post_id, title, body, owner FROM posts
            WHERE post_id IN (SELECT post_id FROM tags WHERE tags = ?)
            AND owner IN (SELECT followed_username FROM follows WHERE follower_username = ?)
            ORDER BY created_at DESC, post_id DESC;
        """, (tag, current_username))
        result = cursor.fetchall()
        return_json = {}
        for i in range(len(result)):
            cursor.execute("SELECT tags FROM tags WHERE post_id = ?;", (result[i][0],))
            result_tags = cursor.fetchall()
            cursor.execute("SELECT COUNT(*) FROM likes WHERE post_id = ?;", (result[i][0],))
            likes = cursor.fetchone()
            return_json[result[i][0]] = {'title': result[i][1], 'body': result[i][2], 'owner': result[i][3], 'tags': [tag[0] for tag in result_tags], 'likes': likes[0]}
        conn.close()
        return json.dumps({'status': 1, 'data': return_json}, ensure_ascii=False)
    

@app.route('/delete', methods=['POST'])
def delete():
    jwt = request.headers['Authorization']
    post_id = request.form.get('post_id')
    username = request.form.get('username')
    if not verify_jwt(jwt):
        return json.dumps({'status': 2})
    encoded_header, encoded_payload, signature = jwt.split('.')
    decoded_payload = base64.urlsafe_b64decode(encoded_payload)
    payload = json.loads(decoded_payload.decode('utf-8'))
    current_username = payload.get('username')
    conn = get_db()
    cursor = conn.cursor()
    if post_id:
        check_moderator = payload.get('moderator')
        cursor.execute("SELECT owner FROM posts WHERE post_id = ?;", (post_id,))
        result = cursor.fetchone()
        if not result:
            conn.close()
            return json.dumps({'status': 2})
        post_owner = result[0]
        if current_username != post_owner and check_moderator != 'True':
            conn.close()
            return json.dumps({'status': 2})
        if check_moderator == 'True' or current_username == post_owner:
            cursor.execute("DELETE FROM posts WHERE post_id = ?;", (post_id,))
            conn.commit()
            conn.close()
            return json.dumps({'status': 1})
    elif username:
        if current_username != username:
            conn.close()
            return json.dumps({'status': 2})
        else:
            cursor.execute("DELETE FROM users WHERE username = ?;", (username,))
            conn.commit()
            conn.close()
            return json.dumps({'status': 1})
    else:
        return json.dumps({'status': 2})


if __name__ == '__main__':
    app.run(debug=True)
