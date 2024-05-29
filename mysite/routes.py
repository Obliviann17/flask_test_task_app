from flask import render_template, request, redirect, flash, url_for, abort
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import check_password_hash, generate_password_hash
from functools import wraps

from mysite.models import User, Role, Ticket, Group
from mysite import app, db

def has_ticket_access(user, ticket):
    if user.role.name == 'Admin':
        return True
    elif user.role.name == 'Manager' or user.role.name == 'Analyst':
        return ticket.group_id == user.group_id
    else:
        return ticket.user_id == user.id

@app.route('/')
def home():
    if current_user.is_authenticated:
        user_login = current_user.login
        user_role = current_user.role if current_user.role else "Unknown"
        user_group = current_user.group if current_user.group else "Not defined"
        return render_template('home.html', title='Home', login=user_login, role=user_role, group=user_group)
    else:
        return render_template('home.html', title='Home')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        login = request.form.get('login')
        role_id = request.form.get('role_id')
        password = request.form.get('password')
        hash_pwd = generate_password_hash(password)

        default_group = Group.query.filter_by(name='Customer 3').first()
        if not default_group:
            default_group = Group(name='Customer 3')
            db.session.add(default_group)
            db.session.commit()

        new_user = User(login=login, password=hash_pwd, role_id=role_id, group=default_group)
        db.session.add(new_user)
        db.session.commit()

        flash('User registered successfully!', 'success')
        return redirect(url_for('login_page'))
    roles = Role.query.all()
    return render_template('register.html', roles=roles)


@app.route('/login', methods=['GET', 'POST'])
def login_page():
    if request.method == 'POST':
        login = request.form.get('login')
        password = request.form.get('password')

        if login and password:
            user = User.query.filter_by(login=login).first()
            if user and check_password_hash(user.password, password):
                login_user(user)
                flash('User logined successfully!', 'success')
                return redirect(url_for('home'))
            else:
                flash('Login or password is not correct', 'danger')
                return render_template('login.html', title='Login')
        else:
            flash('Please fill your login and password fields')
            return render_template('login.html', title='Login', error='Both fields are required.')
    else:
        return render_template('login.html', title='Login')

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    flash('You have successfully logged out!', 'success')
    return redirect(url_for('home'))

@app.route('/tickets')
@login_required
def show_tickets():
    tickets = Ticket.query.all()
    return render_template('tickets.html', tickets=tickets)

@app.route('/create_tickets', methods=['GET', 'POST'])
@login_required
def create_ticket():
    if request.method == 'POST':
        status = request.form.get('status')
        note = request.form.get('note')

        new_ticket = Ticket(status=status, note=note, user_id=current_user.id, group_id=current_user.group.id)
        db.session.add(new_ticket)
        db.session.commit()
        flash('Ticket created successfully!', 'success')
        return redirect(url_for('show_tickets'))

    return render_template('create_tickets.html')

@app.route('/ticket/<int:ticket_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_ticket(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)

    if not has_ticket_access(current_user, ticket):
        flash('You do not have permission to edit this ticket.', 'danger')
        return redirect(url_for('show_tickets'))

    if request.method == 'POST':
        ticket.status = request.form.get('status')
        ticket.note = request.form.get('note')
        try:
            db.session.commit()
            flash('Ticket update successfully!', 'success')
            return redirect(url_for('show_tickets'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating ticket: {str(e)}', 'danger')
            return redirect(url_for('edit_ticket', ticket_id=ticket_id))
    return render_template('edit_ticket.html', ticket=ticket)

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role.name != 'Admin':
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

@app.route('/admin_panel')
@login_required
@admin_required
def admin_panel():
    users = User.query.all()
    roles = Role.query.all()
    return render_template('admin_panel.html', users=users, roles=roles)

@app.route('/admin/edit_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_user(user_id):
    user = User.query.get_or_404(user_id)
    if request.method == 'POST':
        user.login = request.form.get('login')
        user.role_id = request.form.get('role_id')
        user.group_id = request.form.get('group_id')
        db.session.commit()
        flash('User updated successfully!', 'success')
        return redirect(url_for('admin_panel'))
    roles = Role.query.all()
    groups = Group.query.distinct().all()
    return render_template('edit_user.html', user=user, roles=roles, groups=groups)

@app.route('/admin/delete_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash('User deleted successfully!', 'success')
    return redirect(url_for('admin_panel'))
