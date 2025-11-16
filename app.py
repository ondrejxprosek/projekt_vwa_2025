from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import os

app = Flask(__name__)
app.secret_key = 'super_tajne_heslo'  # změň si!

# Nastavení databáze
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(BASE_DIR, 'data.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)


# --- MODELY ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='user')  # admin, manager, user

    def set_password(self, password):
        self.password_hash = generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)


    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(255), nullable=True)


# --- DEKORÁTORY ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Musíš být přihlášen.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


def role_required(*roles):
    def wrapper(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user = User.query.get(session.get('user_id'))
            if not user or user.role not in roles:
                flash('Nemáš oprávnění k této akci.', 'danger')
                return redirect(url_for('index'))
            return f(*args, **kwargs)
        return decorated_function
    return wrapper


# --- ROUTES ---
@app.route('/')
@login_required
def index():
    user = User.query.get(session['user_id'])
    items = Item.query.all()
    return render_template('index.html', items=items, user=user)

@app.context_processor
def inject_user_model():
    return dict(User=User)

@app.route('/admin')
@login_required
@role_required('admin')
def admin_panel():
    users = User.query.all()
    user = User.query.get(session['user_id'])
    return render_template('admin.html', users=users, user=user)


@app.route('/admin/update_role/<int:user_id>', methods=['POST'])
@login_required
@role_required('admin')
def update_role(user_id):
    new_role = request.form.get('role')
    user_to_update = User.query.get(user_id)

    if not user_to_update:
        flash('Uživatel nenalezen.', 'danger')
        return redirect(url_for('admin_panel'))

    if user_to_update.id == session['user_id']:
        flash('Nemůžeš měnit svou vlastní roli.', 'warning')
        return redirect(url_for('admin_panel'))

    user_to_update.role = new_role
    db.session.commit()
    flash(f'Role uživatele {user_to_update.username} byla změněna na {new_role}.', 'success')
    return redirect(url_for('admin_panel'))


@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
@role_required('admin')
def delete_user(user_id):
    user_to_delete = User.query.get(user_id)
    if not user_to_delete:
        flash('Uživatel nenalezen.', 'danger')
        return redirect(url_for('admin_panel'))

    if user_to_delete.id == session['user_id']:
        flash('Nemůžeš smazat sám sebe.', 'warning')
        return redirect(url_for('admin_panel'))

    db.session.delete(user_to_delete)
    db.session.commit()
    flash(f'Uživatel {user_to_delete.username} byl smazán.', 'info')
    return redirect(url_for('admin_panel'))


# --- SPRÁVA POLOŽEK ---
@app.route('/admin/items')
@login_required
@role_required('admin', 'manager')
def admin_items():
    user = User.query.get(session['user_id'])
    items = Item.query.all()
    return render_template('admin_items.html', title='Přehled položek', items=items, user=user)


@app.route('/admin/items/add', methods=['POST'])
@login_required
@role_required('admin', 'manager')
def add_item():
    name = request.form.get('name')
    description = request.form.get('description')
    if not name.strip():
        flash('Název položky nesmí být prázdný.', 'warning')
        return redirect(url_for('admin_items'))
    new_item = Item(name=name, description=description)
    db.session.add(new_item)
    db.session.commit()
    flash('Položka byla přidána.', 'success')
    return redirect(url_for('admin_items'))


@app.route('/admin/items/edit/<int:item_id>', methods=['POST'])
@login_required
@role_required('admin', 'manager')
def edit_item(item_id):
    item = Item.query.get(item_id)
    if not item:
        flash('Položka nenalezena.', 'danger')
        return redirect(url_for('admin_items'))
    item.name = request.form.get('name')
    item.description = request.form.get('description')
    db.session.commit()
    flash('Položka byla upravena.', 'success')
    return redirect(url_for('admin_items'))


@app.route('/admin/items/delete/<int:item_id>', methods=['POST'])
@login_required
@role_required('admin', 'manager')
def delete_item(item_id):
    item = Item.query.get(item_id)
    if not item:
        flash('Položka nenalezena.', 'danger')
        return redirect(url_for('admin_items'))
    db.session.delete(item)
    db.session.commit()
    flash('Položka byla smazána.', 'info')
    return redirect(url_for('admin_items'))


# --- AUTH ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            session['user_id'] = user.id
            flash(f'Vítej zpět, {user.username}!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Neplatné přihlašovací údaje.', 'danger')
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form.get('role', 'user')

        if User.query.filter_by(username=username).first():
            flash('Uživatel již existuje.', 'warning')
            return redirect(url_for('register'))

        new_user = User(username=username, role=role)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        flash('Registrace úspěšná. Nyní se přihlaš.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/admin/add_user', methods=['POST'])
@login_required
@role_required('admin')
def admin_add_user():
    username = request.form.get('username')
    password = request.form.get('password')
    role = request.form.get('role', 'user')

    if not username or not password:
        flash('Uživatelské jméno a heslo jsou povinné.', 'warning')
        return redirect(url_for('admin_panel'))

    if User.query.filter_by(username=username).first():
        flash('Uživatel již existuje.', 'warning')
        return redirect(url_for('admin_panel'))

    new_user = User(username=username, role=role)
    new_user.set_password(password)
    db.session.add(new_user)
    db.session.commit()
    flash(f'Uživatel {username} byl vytvořen.', 'success')
    return redirect(url_for('admin_panel'))

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('Byl jsi odhlášen.', 'info')
    return redirect(url_for('login'))


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
