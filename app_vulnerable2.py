from flask import Flask, request, jsonify
import bcrypt
import sqlite3
import jwt
import datetime
from functools import wraps
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
app.config['DEBUG'] = True

Limiter = Limiter(get_remote_address, app=app, default_limits=["200 per minute"])

SECRET_KEY = "ff5877823aa4b2550e10721b76dd6cb8f12cba5eb857a1ca5454775a85093e1c"
SEGURITY_DB = "segurieva.db"
MINUTES = 5

def get_db_connection():
    return sqlite3.connect(SEGURITY_DB)

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password BLOB NOT NULL,
            email TEXT NOT NULL UNIQUE,
            birth_date DATE NOT NULL,
            status INTEGER NOT NULL DEFAULT 1,
            secret_question TEXT NOT NULL,
            secret_answer TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user'
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT NOT NULL,
            creation_date DATE NOT NULL,
            arrival_price REAL NOT NULL,
            retail_price REAL NOT NULL,
            wholesale_price REAL NOT NULL
        )
    """)
    cursor.execute("SELECT 1 FROM users WHERE username = ?", ('admin',))
    if not cursor.fetchone():
        hashed = bcrypt.hashpw(b"admin2223", bcrypt.gensalt())
        cursor.execute("""
            INSERT INTO users (username, password, email, birth_date, secret_question, secret_answer, role)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, ('admin', hashed, 'admin@gmail.com', '2001-05-22', 'admin?', 'sí', 'admin'))
    conn.commit()
    conn.close()

init_db()

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('x-access-tokens')
        if not token:
            return jsonify({'message': 'Token requerido'}), 401
        try:
            data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            request.user = data
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'El token ha expirado'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'El token es inválido'}), 401
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if request.user.get("role") != "admin":
            return jsonify({'message': 'Nesecitas permiso con el rol de administrador'}), 403
        return f(*args, **kwargs)
    return wrapper

@app.route('/register', methods=['POST'])
@Limiter.limit("5 per minute")
def register():
    data = request.get_json()
    required = ['username', 'password', 'email', 'birth_date', 'secret_question', 'secret_answer']
    if not all(data.get(k) for k in required):
        return jsonify({'message': 'Faltan campos obligatorios'}), 400
    hashed = bcrypt.hashpw(data['password'].encode('utf-8'), bcrypt.gensalt())
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO users (username, password, email, birth_date, secret_question, secret_answer)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            data['username'], hashed, data['email'],
            data['birth_date'], data['secret_question'], data['secret_answer']
        ))
        conn.commit()
        return jsonify({'message': 'Registro exitoso'}), 201
    except sqlite3.IntegrityError:
        return jsonify({'message': 'El correo ya existe'}), 400
    finally:
        conn.close()

@app.route('/login', methods=['POST'])
@Limiter.limit("10 per minute")
def login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, password, role, status FROM users WHERE username=?", (username,))
    user = cursor.fetchone()
    conn.close()
    if not user or not bcrypt.checkpw(password.encode('utf-8'), user[2]):
        return jsonify({'message': 'Credenciales incorrectas'}), 401
    if user[4] != 1:
        return jsonify({'message': 'el usuario no esta activo'}), 403
    token = jwt.encode({
        'user_id': user[0],
        'username': user[1],
        'role': user[3],
        'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=MINUTES)
    }, SECRET_KEY, algorithm='HS256')
    return jsonify({'message': 'Login con exitoso', 'token': token}), 200

@app.route('/products_list', methods=['GET'])
@token_required
def list_products():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM products")
    rows = cursor.fetchall()
    conn.close()
    products = [{
        "id": r[0], "name": r[1], "description": r[2],
        "creation_date": r[3], "arrival_price": r[4],
        "retail_price": r[5], "wholesale_price": r[6]
    } for r in rows]
    return jsonify(products), 200

def validate_product_data(data):
    if not all(data.get(f) for f in ['name','description','creation_date','arrival_price','retail_price','wholesale_price']):
        return False
    try:
        float(data['arrival_price'])
        float(data['retail_price'])
        float(data['wholesale_price'])
        datetime.datetime.strptime(data['creation_date'], '%Y-%m-%d')
    except:
        return False
    return True

@app.route('/products_create', methods=['POST'])
@token_required
@admin_required
def create_product():
    data = request.get_json()
    if not validate_product_data(data):
        return jsonify({'message': 'Datos de producto inválidos'}), 400
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO products (name, description, creation_date, arrival_price, retail_price, wholesale_price)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        data['name'], data['description'], data['creation_date'],
        float(data['arrival_price']), float(data['retail_price']), float(data['wholesale_price'])
    ))
    conn.commit()
    conn.close()
    return jsonify({'message': 'El producto fue creado correctamente'}), 201

@app.route('/products_update', methods=['POST'])
@token_required
@admin_required
def update_product():
    data = request.get_json()
    if not validate_product_data(data) or not data.get('id'):
        return jsonify({'message': 'Datos de producto inválidos'}), 400
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE products SET name=?, description=?, creation_date=?, arrival_price=?, retail_price=?, wholesale_price=? WHERE id=?
    """, (
        data['name'], data['description'], data['creation_date'],
        float(data['arrival_price']), float(data['retail_price']), float(data['wholesale_price']),
        data['id']
    ))
    conn.commit()
    affected = cursor.rowcount
    conn.close()
    if affected == 0:
        return jsonify({'message': 'El producto no fue encontrado'}), 404
    return jsonify({'message': 'El producto fue actualizado correctamente'}), 200

@app.route('/products_delete', methods=['POST'])
@token_required
@admin_required
def delete_product():
    data = request.get_json()
    product_id = data.get("id")
    if not product_id:
        return jsonify({'message': 'ID de producto requerido'}), 400
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM products WHERE id=?", (product_id,))
    conn.commit()
    deleted = cursor.rowcount
    conn.close()
    if deleted == 0:
        return jsonify({'message': 'El poducto fue encontrado'}), 404
    return jsonify({'message': 'El producto fue eliminado correctamente'}), 200

if __name__ == '__main__':
    app.run(debug=True)
