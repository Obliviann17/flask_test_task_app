from flask import Flask
from flask_login import LoginManager
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy


app = Flask(__name__)
app.config['SECRET_KEY'] = 'a856c71e22c092d58ecad2ab1e63a4ee'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['FLASK_ADMIN_SWATCH'] = 'cerulean'

db = SQLAlchemy(app)
migrate = Migrate(app, db)
manager = LoginManager(app)


from mysite import models, routes

if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)