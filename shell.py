from app import app, db, Item

ctx = app.app_context()
ctx.push()  # aktivuje kontext

print("App context aktivní, můžeš pracovat s DB.")