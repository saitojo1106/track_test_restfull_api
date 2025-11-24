import sqlite3
import base64
import re
from functools import wraps
from flask import Flask, request, jsonify, g

app = Flask(__name__)
DB_NAME = "database.db"

# --- DB設定 ---
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DB_NAME)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        # 仕様に合わせて nickname と comment を追加
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                user_id TEXT PRIMARY KEY,
                password TEXT NOT NULL,
                nickname TEXT NOT NULL,
                comment TEXT
            )
        ''')
        db.commit()

# --- 認証デコレーター ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            # 仕様書の失敗レスポンスに合わせる
            return jsonify({"message": "Authentication failed"}), 401
        
        try:
            auth_type, auth_token = auth_header.split()
            if auth_type.lower() != 'basic':
                raise ValueError
            decoded_str = base64.b64decode(auth_token).decode('utf-8')
            if ':' not in decoded_str:
                 raise ValueError
            user_id, password = decoded_str.split(':', 1)

            db = get_db()
            user = db.execute(
                'SELECT * FROM users WHERE user_id = ? AND password = ?', 
                (user_id, password)
            ).fetchone()

            if user is None:
                # デバッグ: ユーザーの存在確認
                print(f"[DEBUG] Auth failed for user_id: {user_id}")
                exists = db.execute('SELECT user_id FROM users WHERE user_id = ?', (user_id,)).fetchone()
                print(f"[DEBUG] User exists: {exists is not None}")
                return jsonify({"message": "Authentication failed"}), 401
            
            g.current_user = user
        except Exception as e:
            print(f"[DEBUG] Auth exception: {e}")
            return jsonify({"message": "Authentication failed"}), 401

        return f(*args, **kwargs)
    return decorated_function

# --- API エンドポイント ---

# 1. アカウント作成
@app.route('/signup', methods=['POST'])
def signup():
    # 1. JSONデータの取得
    data = request.get_json()
    if not data:
        return jsonify({"message": "Account creation failed", "cause": "required user_id and password"}), 400

    user_id = data.get("user_id")
    password = data.get("password")
    # nicknameがない場合はuser_idと同じにする仕様
    nickname = data.get("nickname") or user_id 
    comment = data.get("comment", "")

    # 2. 必須チェック (required user_id and password)
    if not user_id or not password:
        return jsonify({
            "message": "Account creation failed", 
            "cause": "required user_id and password"
        }), 400

    # 3. 文字数チェック (input length is incorrect)
    # user_id: 6~20文字, password: 8~20文字, nickname: 30文字以下, comment: 100文字以下
    if not (6 <= len(user_id) <= 20) or not (8 <= len(password) <= 20):
        return jsonify({
            "message": "Account creation failed", 
            "cause": "input length is incorrect"
        }), 400
    
    # nickname は30文字以下、comment は100文字以下
    if len(nickname) > 30 or len(comment) > 100:
        return jsonify({
            "message": "Account creation failed", 
            "cause": "input length is incorrect"
        }), 400

    # 4. 文字種チェック (incorrect character pattern)
    # user_id: 半角英数字のみ
    if not re.match(r"^[a-zA-Z0-9]+$", user_id):
        return jsonify({
            "message": "Account creation failed", 
            "cause": "incorrect character pattern"
        }), 400
    
    # password: 半角英数字記号 (ASCII印字可能文字)
    # \x21-\x7E はスペースなどを除く記号と英数字を表します
    if not re.match(r"^[\x21-\x7E]+$", password):
         return jsonify({
            "message": "Account creation failed", 
            "cause": "incorrect character pattern"
        }), 400

    # 5. データベースへの保存
    db = get_db()
    cursor = db.cursor()
    try:
        cursor.execute(
            'INSERT INTO users (user_id, password, nickname, comment) VALUES (?, ?, ?, ?)',
            (user_id, password, nickname, comment)
        )
        db.commit()
    except sqlite3.IntegrityError:
        # 重複エラー (already same user_id is used)
        return jsonify({
            "message": "Account creation failed", 
            "cause": "already same user_id is used"
        }), 400

    # 6. 成功レスポンス
    return jsonify({
        "message": "Account successfully created",
        "user": {
            "user_id": user_id,
            "nickname": nickname
        }
    }), 200

# 2. ユーザー情報取得
@app.route('/users/<user_id>', methods=['GET'])
@login_required
def get_user(user_id):
    # 認証は必須だが、他のユーザーの情報も取得可能
    db = get_db()
    user = db.execute(
        'SELECT user_id, nickname, comment FROM users WHERE user_id = ?',
        (user_id,)
    ).fetchone()
    
    if user is None:
        return jsonify({"message": "No user found"}), 404

    return jsonify({
        "message": "User details by user_id",
        "user": {
            "user_id": user['user_id'],
            "nickname": user['nickname'],
            "comment": user['comment']
        }
    }), 200

# 3. ユーザー情報更新
@app.route('/users/<user_id>', methods=['PATCH'])
@login_required
def update_user(user_id):
    # 認証されたユーザーと異なるuser_idの場合は権限なし
    if g.current_user['user_id'] != user_id:
        return jsonify({"message": "No permission for update"}), 403
    
    data = request.get_json()
    if not data:
        return jsonify({
            "message": "User updation failed",
            "cause": "required nickname or comment"
        }), 400
    
    nickname = data.get("nickname")
    comment = data.get("comment")
    
    # nicknameもcommentも指定されていない場合
    if nickname is None and comment is None:
        return jsonify({
            "message": "User updation failed",
            "cause": "required nickname or comment"
        }), 400
    
    # 文字数チェック
    if nickname is not None and len(nickname) > 30:
        return jsonify({
            "message": "User updation failed",
            "cause": "String length limit exceeded or containing invalid characters"
        }), 400
    
    if comment is not None and len(comment) > 100:
        return jsonify({
            "message": "User updation failed",
            "cause": "String length limit exceeded or containing invalid characters"
        }), 400
    
    # データベース更新
    db = get_db()
    
    # nicknameとcommentのどちらが指定されたかで更新内容を変える
    if nickname is not None and comment is not None:
        db.execute(
            'UPDATE users SET nickname = ?, comment = ? WHERE user_id = ?',
            (nickname, comment, user_id)
        )
    elif nickname is not None:
        db.execute(
            'UPDATE users SET nickname = ? WHERE user_id = ?',
            (nickname, user_id)
        )
    elif comment is not None:
        db.execute(
            'UPDATE users SET comment = ? WHERE user_id = ?',
            (comment, user_id)
        )
    
    db.commit()
    
    # 更新後のユーザー情報を取得
    updated_user = db.execute(
        'SELECT nickname, comment FROM users WHERE user_id = ?',
        (user_id,)
    ).fetchone()
    
    return jsonify({
        "message": "User successfully updated",
        "user": {
            "nickname": updated_user['nickname'],
            "comment": updated_user['comment']
        }
    }), 200

# 4. アカウント削除
@app.route('/close', methods=['POST'])
@login_required
def close_account():
    db = get_db()
    db.execute('DELETE FROM users WHERE user_id = ?', (g.current_user['user_id'],))
    db.commit()
    
    return jsonify({"message": "Account and user successfully removed"}), 200

# Gunicorn（本番）でも実行されるように、if文の外に出す
with app.app_context():
    init_db()

if __name__ == '__main__':
    app.run(debug=True, port=8000)