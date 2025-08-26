from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from apscheduler.schedulers.background import BackgroundScheduler
import smtplib
import socket
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Dummy data for servers
servers = [
    {"server_name": "Server1", "status": "Online", "ip": "192.168.1.1"},
    {"server_name": "Server2", "status": "Offline", "ip": "192.168.1.2"},
]

# Dummy data for firewall rules
firewall_rules = [
    {"source_ip": "192.168.1.100", "action": "Allow"},
    {"source_ip": "192.168.1.101", "action": "Deny"},
]

# Dummy data for user accounts
users = [
    {"username": "admin", "password": generate_password_hash("admin_password"), "role": "admin"},
    {"username": "user", "password": generate_password_hash("user_password"), "role": "user"},
]

def notify_admin(server):
    admin_email = "admin@gmail.com"  # Replace with the actual admin email
    subject = f"Server {server['server_name']} is Down"
    body = f"The server {server['server_name']} (IP: {server['ip']}) is currently down."

    msg = MIMEMultipart()
    msg['From'] = "client@gmail.com"  # Replace with your Gmail address
    msg['To'] = admin_email
    msg['Subject'] = subject

    msg.attach(MIMEText(body, 'plain'))

    try:
        smtp_server = smtplib.SMTP('smtp.gmail.com', 587)
        smtp_server.starttls()
        smtp_server.login("client@gmail.com", "ddksgzagcznrgsav")  # Replace with your Gmail address and app password
        smtp_server.sendmail("client@gmail.com", admin_email, msg.as_string())
        smtp_server.quit()
        print("Email sent successfully.")
    except socket.gaierror as e:
        print(f"Failed to send email notification: {e.strerror}. Please check the SMTP server address.")
    except smtplib.SMTPAuthenticationError as e:
        print(f"SMTP authentication error: {str(e)}. Please check your email credentials.")
    except smtplib.SMTPConnectError as e:
        print(f"SMTP connection error: {str(e)}. Please check your network connection.")
    except smtplib.SMTPException as e:
        print(f"Failed to send email notification: {str(e)}. Please check the SMTP server settings.")
    except Exception as e:
        print(f"An unexpected error occurred: {str(e)}")

# Function to check server statuses
def check_servers():
    for server in servers:
        if server['status'] == 'Offline':
            notify_admin(server)

@app.route('/')
def index():
    if 'username' in session:
        return render_template('index.html', user=get_user(), servers=servers, firewall_rules=firewall_rules)
    else:
        return redirect(url_for('main_login'))

@app.route('/main_login', methods=['GET', 'POST'])
def main_login():
    if request.method == 'POST':
        try:
            username = request.form['username']
            password = request.form['password']
        except KeyError as e:
            flash(f'Missing form key: {e.args[0]}', 'danger')
            return render_template('main_login.html')

        user = next((u for u in users if u['username'] == username), None)
        if user and check_password_hash(user['password'], password):
            session['username'] = username
            flash('Logged in successfully', 'success')
            return redirect(url_for('index'))
        else:
            flash('Login failed. Please check your username and password.', 'danger')
    return render_template('main_login.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('main_login'))

# Helper function to get the currently logged-in user
def get_user():
    if 'username' in session:
        username = session['username']
        user = next((u for u in users if u['username'] == username), None)
        return user
    return None

@app.route('/add_server', methods=['GET', 'POST'])
def add_server():
    if 'username' in session:
        user = get_user()
        if user and user['role'] == 'admin':
            if request.method == 'POST':
                server_name = request.form['server_name']
                status = request.form['status']
                ip = request.form['ip']

                new_server = {
                    'server_name': server_name,
                    'status': status,
                    'ip': ip
                }
                servers.append(new_server)
                flash(f'Server {server_name} has been added successfully', 'success')
                return redirect(url_for('index'))
            return render_template('add_server.html', user=user)
        else:
            flash('Access denied. You do not have permission to add details.', 'danger')
    else:
        return redirect(url_for('main_login'))

@app.route('/add_firewall_rule', methods=['GET', 'POST'])
def add_firewall_rule():
    if 'username' in session:
        user = get_user()
        if user and user['role'] == 'admin':
            if request.method == 'POST':
                source_ip = request.form['source_ip']
                action = request.form['action']

                new_rule = {
                    'source_ip': source_ip,
                    'action': action
                }
                firewall_rules.append(new_rule)
                flash('Firewall rule has been added successfully', 'success')
                return redirect(url_for('index'))
            return render_template('add_firewall_rule.html', user=user)
        else:
            flash('Access denied. You do not have permission to add details.', 'danger')
    else:
        return redirect(url_for('main_login'))


@app.route('/toggle_server_status/<server_name>')
def toggle_server_status(server_name):
    if 'username' in session:
        user = get_user()
        if user and user['role'] == 'admin':
            server = next((s for s in servers if s['server_name'] == server_name), None)
            if server:
                server['status'] = 'Online' if server['status'] == 'Offline' else 'Offline'
                
                # Check if the server status is now 'Offline' and trigger email notification
                if server['status'] == 'Offline':
                    notify_admin(server)
                
                flash(f'Server {server_name} status has been toggled.', 'success')
            else:
                flash('Server not found.', 'danger')
            return redirect(url_for('index'))
        else:
            flash('Access denied. You do not have permission to toggle server status.', 'danger')
    else:
        return redirect(url_for('main_login'))


@app.route('/toggle_firewall_action/<source_ip>')
def toggle_firewall_action(source_ip):
    if 'username' in session:
        user = get_user()
        if user and user['role'] == 'admin':
            rule = next((r for r in firewall_rules if r['source_ip'] == source_ip), None)
            if rule:
                rule['action'] = 'Allow' if rule['action'] == 'Deny' else 'Deny'
                flash(f'Firewall action for {source_ip} has been toggled.', 'success')
            else:
                flash('Firewall rule not found.', 'danger')
            return redirect(url_for('index'))
        else:
            flash('Access denied. You do not have permission to toggle firewall action.', 'danger')
    else:
        return redirect(url_for('main_login'))

@app.route('/test_email')
def test_email():
    if 'username' in session:
        user = get_user()
        if user and user['role'] == 'admin':
            notify_admin(servers[0])  # Test with the first server
            flash('Test email sent.', 'success')
            return redirect(url_for('index'))
        else:
            flash('Access denied.', 'danger')
    return redirect(url_for('main_login'))

if __name__ == '__main__':
    scheduler = BackgroundScheduler()
    scheduler.add_job(func=check_servers, trigger="interval", minutes=1)
    scheduler.start()

    try:
        app.run(debug=True)
    except (KeyboardInterrupt, SystemExit):
        scheduler.shutdown()
