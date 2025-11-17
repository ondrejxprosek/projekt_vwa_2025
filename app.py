from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime
import os

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY') or os.urandom(24)

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

# --- nový model pro účet (order) a položky účtu ---
class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    table_id = db.Column(db.Integer, db.ForeignKey('table.id'), nullable=False)
    opened_at = db.Column(db.DateTime, default=datetime.utcnow)
    closed_at = db.Column(db.DateTime, nullable=True)
    note = db.Column(db.String(255), nullable=True)

    table = db.relationship('Table', backref=db.backref('orders', lazy='dynamic'))

class OrderItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'), nullable=False)
    item_id = db.Column(db.Integer, db.ForeignKey('item.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    quantity = db.Column(db.Integer, default=1)
    price = db.Column(db.Float, nullable=False)  # cena v čase přidání

    order = db.relationship('Order', backref=db.backref('items', lazy='dynamic'))
    item = db.relationship('Item')

class Permission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    role = db.Column(db.String(50), unique=True, nullable=False)  # 'user' | 'manager' | 'admin'
    can_cashier = db.Column(db.Boolean, default=False)
    can_view_closed_orders = db.Column(db.Boolean, default=False)
    can_manage_tables = db.Column(db.Boolean, default=False)
    can_manage_items = db.Column(db.Boolean, default=False)
    can_manage_users = db.Column(db.Boolean, default=False)

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
    # Základní statistiky
    total_items = Item.query.count()
    total_tables = Table.query.count()
    total_users = User.query.count()
    
    # Filtr tržeb – výchozí dnešní den
    date_filter = request.args.get('date', datetime.utcnow().strftime('%Y-%m-%d'))
    try:
        filter_date = datetime.strptime(date_filter, '%Y-%m-%d')
    except ValueError:
        filter_date = datetime.utcnow()
    
    # Tržby za zvolený den (uzavřené účty)
    start_of_day = filter_date.replace(hour=0, minute=0, second=0, microsecond=0)
    end_of_day = filter_date.replace(hour=23, minute=59, second=59, microsecond=999999)
    
    closed_orders = Order.query.filter(
        Order.closed_at >= start_of_day,
        Order.closed_at <= end_of_day
    ).all()
    
    daily_revenue = 0.0
    for order in closed_orders:
        for item in order.items:
            daily_revenue += (item.price or 0) * (item.quantity or 1)
    
    return render_template(
        'index.html',
        total_items=total_items,
        total_tables=total_tables,
        total_users=total_users,
        daily_revenue=daily_revenue,
        date_filter=filter_date.strftime('%Y-%m-%d'),
        title='Dashboard'
    )

@app.context_processor
def inject_user_model():
    return dict(User=User)

@app.context_processor
def inject_db():
    return dict(db=db)

@app.context_processor
def inject_auth():
    from flask import session
    u = None
    perms = dict(
        can_cashier=False,
        can_view_closed_orders=False,
        can_manage_tables=False,
        can_manage_items=False,
        can_manage_users=False,
    )
    if 'user_id' in session:
        u = User.query.get(session['user_id'])
        if u:
            if u.role == 'admin':
                # Admin má všechna práva
                for k in perms.keys():
                    perms[k] = True
            else:
                # Načti práva z DB pro aktuální roli
                p = Permission.query.filter_by(role=u.role).first()
                if p:
                    perms.update(dict(
                        can_cashier=p.can_cashier,
                        can_view_closed_orders=p.can_view_closed_orders,
                        can_manage_tables=p.can_manage_tables,
                        can_manage_items=p.can_manage_items,
                        can_manage_users=p.can_manage_users,
                    ))
    return dict(current_user=u, perms=perms, user=u, me=u)

# přidej tohle:
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
    # Zkontroluj, zda existuje admin
    admin_exists = User.query.filter_by(role='admin').first() is not None
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Pokud existuje admin, nový uživatel může být jen 'user'
        if admin_exists:
            role = 'user'
        else:
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

    return render_template('register.html', admin_exists=admin_exists)

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
    # Načti otevřený účet pro každý stůl
    for table in tables_list:
        table.open_order = Order.query.filter_by(
            table_id=table.id, 
            closed_at=None
        ).order_by(Order.opened_at.desc()).first()
    
    return render_template(
        'cashier.html', 
        tables=tables_list, 
        order=None, 
        items=None, 
        title='Pokladna'
    )

@app.route('/cashier/open/<int:table_id>')
@login_required
def cashier_open(table_id):
    order = Order.query.filter_by(table_id=table_id, closed_at=None).order_by(Order.opened_at.desc()).first()
    if not order:
        order = Order(table_id=table_id, opened_at=datetime.utcnow())
        db.session.add(order)
        db.session.commit()
    return redirect(url_for('cashier_order', order_id=order.id))

# Opustit stůl (neuzavírá účet, pouze se vrátí na seznam stolů)
@app.route('/cashier/leave/<int:order_id>')
@login_required
def cashier_leave(order_id):
    return redirect(url_for('cashier'))

# Zobrazení otevřeného účtu s položkami a seznamem položek k přidání
@app.route('/cashier/order/<int:order_id>')
@login_required
def cashier_order(order_id):
    order = Order.query.get(order_id)
    if not order:
        flash('Účet nenalezen.', 'danger')
        return redirect(url_for('cashier'))
    items = Item.query.all()
    order_items = order.items.order_by(OrderItem.timestamp).all()
    return render_template('cashier.html', tables=None, order=order, items=items, order_items=order_items, title=f'Pokladna - {order.table.name}')

# přidat položku do účtu
@app.route('/cashier/order/<int:order_id>/add_item', methods=['POST'])
@login_required
def cashier_add_item(order_id):
    order = Order.query.get(order_id)
    if not order or order.closed_at is not None:
        flash('Nelze přidat položku do neexistujícího/uzavřeného účtu.', 'danger')
        return redirect(url_for('cashier'))
    item_id = request.form.get('item_id')
    qty = int(request.form.get('quantity', 1) or 1)
    if not item_id:
        flash('Chyba: položka nebyla zvolena.', 'danger')
        return redirect(url_for('cashier_order', order_id=order_id))
    item = Item.query.get(int(item_id))
    if not item:
        flash('Položka nenalezena.', 'danger')
        return redirect(url_for('cashier_order', order_id=order_id))
    oi = OrderItem(order_id=order.id, item_id=item.id, quantity=qty, price=item.price, timestamp=datetime.utcnow())
    db.session.add(oi)
    db.session.commit()
    flash('Položka přidána do účtu.', 'success')
    return redirect(url_for('cashier_order', order_id=order_id))

# Náhled uzavření účtu (soupis + celkem)
@app.route('/cashier/order/<int:order_id>/close_preview')
@login_required
def cashier_close_preview(order_id):
    order = Order.query.get(order_id)
    if not order:
        flash('Účet nenalezen.', 'danger')
        return redirect(url_for('cashier'))
    items = order.items.order_by(OrderItem.timestamp).all()
    total = sum((it.price or 0) * (it.quantity or 1) for it in items)
    return render_template('cashier_close.html', order=order, items=items, total=total)

# Zaplatit a uzavřít účet (vytvoří záznam closed_at)
@app.route('/cashier/order/<int:order_id>/pay', methods=['POST'])
@login_required
def cashier_pay(order_id):
    order = Order.query.get(order_id)
    if not order or order.closed_at is not None:
        flash('Účet nenalezen nebo je již uzavřen.', 'danger')
        return redirect(url_for('cashier'))
    items = order.items.order_by(OrderItem.timestamp).all()
    total = sum((it.price or 0) * (it.quantity or 1) for it in items)
    order.closed_at = datetime.utcnow()
    db.session.commit()
    # zobrazit stránku k tisku (receipt.html) nebo přesměrovat podle implementace
    return render_template('receipt.html', order=order, items=items, total=total)

@app.route('/closed_orders')
@login_required
@role_required('admin', 'manager')
def closed_orders():
    orders = Order.query.filter(Order.closed_at != None).order_by(Order.closed_at.desc()).all()
    return render_template('closed_orders.html', orders=orders, title='Uzavřené účty')


@app.route('/order/<int:order_id>')
@login_required
@role_required('admin', 'manager')
def view_order(order_id):
    order = Order.query.get(order_id)
    if not order:
        flash('Účet nenalezen.', 'danger')
        return redirect(url_for('closed_orders'))
    items = order.items.order_by(OrderItem.timestamp).all()
    total = sum((it.price or 0) * (it.quantity or 1) for it in items)
    return render_template('order_detail.html', order=order, items=items, total=total, title=f'Detail účtu #{order.id}')


@app.route('/admin/permissions', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def admin_permissions():
    if request.method == 'POST':
        role = request.form.get('role')
        perm = Permission.query.filter_by(role=role).first()
        if not perm:
            perm = Permission(role=role)
            db.session.add(perm)
        
        perm.can_cashier = 'can_cashier' in request.form
        perm.can_view_closed_orders = 'can_view_closed_orders' in request.form
        perm.can_manage_tables = 'can_manage_tables' in request.form
        perm.can_manage_items = 'can_manage_items' in request.form
        perm.can_manage_users = 'can_manage_users' in request.form
        
        db.session.commit()
        flash(f'Práva pro roli "{role}" aktualizována.', 'success')
        return redirect(url_for('admin_permissions'))
    
    permissions = Permission.query.all()
    # Ujisti se, že všechny role existují v DB
    for role_name in ['user', 'manager', 'admin']:
        if not any(p.role == role_name for p in permissions):
            permissions.append(Permission(role=role_name))
    
    return render_template('admin_permissions.html', permissions=permissions, title='Správa práv')

def ensure_schema():
    try:
        if db.engine.url.get_backend_name() == 'sqlite':
            with db.engine.begin() as conn:
                cols = [row[1] for row in conn.execute(db.text("PRAGMA table_info(item)")).fetchall()]
                if 'created_at' not in cols:
                    conn.execute(db.text("ALTER TABLE item ADD COLUMN created_at DATETIME"))
                    conn.execute(db.text("UPDATE item SET created_at = CURRENT_TIMESTAMP WHERE created_at IS NULL"))
    except Exception as e:
        app.logger.error(f'ensure_schema failed: {e}')


def ensure_default_permissions():
    defaults = {
        'admin':   dict(can_cashier=True, can_view_closed_orders=True, can_manage_tables=True, can_manage_items=True, can_manage_users=True),
        'manager': dict(can_cashier=True, can_view_closed_orders=True, can_manage_tables=True, can_manage_items=True, can_manage_users=False),
        'user':    dict(can_cashier=True, can_view_closed_orders=False, can_manage_tables=False, can_manage_items=False, can_manage_users=False),
    }
    for role, flags in defaults.items():
        perm = Permission.query.filter_by(role=role).first()
        if not perm:
            db.session.add(Permission(role=role, **flags))
    db.session.commit()

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        ensure_schema()  # pro item.created_at
        ensure_default_permissions()  # pro Permission
    app.run(debug=True)
