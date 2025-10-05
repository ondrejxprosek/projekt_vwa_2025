from flask import Flask
from flask_sqlalchemy import SQLAlchemy
import os

app = Flask(__name__)

# Nastavení cesty k SQLite databázi
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(BASE_DIR, 'data.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Definuj model (tabulku)
class Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)

# Hlavní route
@app.route('/')
def index():
    items = Item.query.all()
    return '<br>'.join([item.name for item in items]) or "Databáze je prázdná."

# Spuštění aplikace
if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Vytvoří databázi při prvním spuštění
    app.run(debug=True)
