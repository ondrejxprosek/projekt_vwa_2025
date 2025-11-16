from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import os
from datetime import datetime

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
    price = db.Column(db.Float, nullable=False)  # přidej tohle
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Table(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class TableSession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    table_id = db.Column(db.Integer, db.ForeignKey('table.id'), nullable=False)
    opened_at = db.Column(db.DateTime, default=datetime.utcnow)
    closed_at = db.Column(db.DateTime, nullable=True)

    table = db.relationship('Table', backref=db.backref('sessions', lazy='dynamic'))

class TableItemEntry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.Integer, db.ForeignKey('table_session.id'), nullable=False)
    item_id = db.Column(db.Integer, db.ForeignKey('item.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    quantity = db.Column(db.Integer, default=1)

    session = db.relationship('TableSession', backref=db.backref('entries', lazy='dynamic'))
    item = db.relationship('Item')

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
def admin_items_add():
    name = request.form.get('name')
    description = request.form.get('description')
    price = request.form.get('price')
    
    if not name or not price:
        flash('Název a cena jsou povinné', 'danger')
        return redirect(url_for('admin_items'))
    
    try:
        new_item = Item(name=name, description=description, price=float(price))
        db.session.add(new_item)
        db.session.commit()
        flash(f'Položka "{name}" přidána', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Chyba: {str(e)}', 'danger')
    
    return redirect(url_for('admin_items'))


@app.route('/admin/items/edit/<int:item_id>', methods=['POST'])
@login_required
@role_required('admin', 'manager')
def edit_item(item_id):
    item = Item.query.get(item_id)
    if not item:
        flash('Položka nenalezena', 'danger')
        return redirect(url_for('admin_items'))
    
    item.name = request.form.get('name')
    item.description = request.form.get('description')
    item.price = float(request.form.get('price', item.price))
    db.session.commit()
    flash('Položka aktualizována', 'success')
    return redirect(url_for('admin_items'))


@app.route('/admin/items/delete/<int:item_id>', methods=['POST'])
@login_required
@role_required('admin', 'manager')
def delete_item(item_id):
    item = Item.query.get(item_id)
    if item:
        db.session.delete(item)
        db.session.commit()
        flash('Položka smazána', 'success')
    return redirect(url_for('admin_items'))


# ROUTES pro správu stolů
@app.route('/tables')
@login_required
@role_required('admin', 'manager')
def tables():
    tables = Table.query.order_by(Table.id).all()
    return render_template('tables.html', tables=tables, title='Stoly')

@app.route('/tables/add', methods=['POST'])
@login_required
@role_required('admin', 'manager')
def add_table():
    name = request.form.get('name')
    description = request.form.get('description')
    if not name:
        flash('Název stolu je povinný', 'danger')
        return redirect(url_for('tables'))
    t = Table(name=name, description=description)
    db.session.add(t)
    db.session.commit()
    flash('Stůl přidán', 'success')
    return redirect(url_for('tables'))

@app.route('/tables/edit/<int:table_id>', methods=['POST'])
@login_required
@role_required('admin', 'manager')
def edit_table(table_id):
    t = Table.query.get(table_id)
    if not t:
        flash('Stůl nenalezen', 'danger')
        return redirect(url_for('tables'))
    t.name = request.form.get('name') or t.name
    t.description = request.form.get('description') or t.description
    db.session.commit()
    flash('Stůl upraven', 'success')
    return redirect(url_for('tables'))

@app.route('/tables/delete/<int:table_id>', methods=['POST'])
@login_required
@role_required('admin', 'manager')
def delete_table(table_id):
    t = Table.query.get(table_id)
    if t:
        db.session.delete(t)
        db.session.commit()
        flash('Stůl smazán', 'success')
    else:
        flash('Stůl nenalezen', 'danger')
    return redirect(url_for('tables'))


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

# přehled stolů (default po kliknutí na Pokladna)
@app.route('/cashier')
@login_required
def cashier():
    tables_list = Table.query.order_by(Table.id).all()
    return render_template('cashier.html', tables=tables_list, session_obj=None, items=None, title='Pokladna')

# otevřít (nebo znovu použít) session pro stůl
@app.route('/cashier/open/<int:table_id>')
@login_required
def cashier_open(table_id):
    # zkontroluj existující otevřenou session
    sess = TableSession.query.filter_by(table_id=table_id, closed_at=None).first()
    if not sess:
        sess = TableSession(table_id=table_id)
        db.session.add(sess)
        db.session.commit()
    return redirect(url_for('cashier_session', session_id=sess.id))

# zobrazení session s položkami
@app.route('/cashier/session/<int:session_id>')
@login_required
def cashier_session(session_id):
    sess = TableSession.query.get(session_id)
    if not sess:
        flash('Session nenalezena.', 'danger')
        return redirect(url_for('cashier'))
    items = Item.query.all()
    # načti existující položky pro session (seřazeny dle času)
    entries = sess.entries.order_by(TableItemEntry.timestamp).all()
    return render_template('cashier.html', tables=None, session_obj=sess, items=items, entries=entries, title=f'Pokladna - {sess.table.name}')

# přidat položku do otevřené session
@app.route('/cashier/session/<int:session_id>/add_item', methods=['POST'])
@login_required
def cashier_add_item(session_id):
    sess = TableSession.query.get(session_id)
    if not sess:
        flash('Session nenalezena.', 'danger')
        return redirect(url_for('cashier'))
    item_id = request.form.get('item_id')
    if not item_id:
        flash('Chyba: položka nebyla zvolena.', 'danger')
        return redirect(url_for('cashier_session', session_id=session_id))
    entry = TableItemEntry(session_id=sess.id, item_id=int(item_id), quantity=int(request.form.get('quantity', 1)))
    db.session.add(entry)
    db.session.commit()
    flash('Položka přidána ke stolu.', 'success')
    return redirect(url_for('cashier_session', session_id=session_id))

# zavřít session (volitelně)
@app.route('/cashier/session/<int:session_id>/close', methods=['POST'])
@login_required
def cashier_close_session(session_id):
    sess = TableSession.query.get(session_id)
    if sess and sess.closed_at is None:
        sess.closed_at = datetime.utcnow()
        db.session.commit()
        flash('Session uzavřena.', 'info')
    return redirect(url_for('cashier'))


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
