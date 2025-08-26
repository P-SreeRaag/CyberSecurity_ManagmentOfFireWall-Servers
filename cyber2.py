from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from sklearn.ensemble import IsolationForest
import numpy as np
import pandas as pd
import pickle
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

# Dummy data for load balancers
load_balancers = [
    {"name": "LB1", "ip": "192.168.1.10", "status": "Active"},
    {"name": "LB2", "ip": "192.168.1.11", "status": "Inactive"},
]

# Email configuration
admin_email = "admin@gmail.com"  # Replace with your actual admin email
smtp_server_address = 'smtp.gmail.com'
smtp_server_port = 587
smtp_username = "client@gmail.com"  # Replace with your actual email
smtp_password = "ddksgzagcznrgsav"  # Replace with your app password

def send_email(subject, body):
    msg = MIMEMultipart()
    msg['From'] = smtp_username
    msg['To'] = admin_email
    msg['Subject'] = subject

    msg.attach(MIMEText(body, 'plain'))

    try:
        smtp_server = smtplib.SMTP(smtp_server_address, smtp_server_port)
        smtp_server.starttls()
        smtp_server.login(smtp_username, smtp_password)
        smtp_server.sendmail(smtp_username, admin_email, msg.as_string())
        smtp_server.quit()
        print("Email sent successfully.")
    except (socket.gaierror, smtplib.SMTPAuthenticationError, smtplib.SMTPConnectError, smtplib.SMTPException) as e:
        print(f"Failed to send email notification: {e}")

# Initialize and train Isolation Forest
def train_isolation_forest():
    data = [
        [10, 1],  # Normal behavior
        [15, 0],  # Normal behavior
        [30, 5],  # Normal behavior
        [100, 50],# Anomalous behavior
        [5, 10],  # Anomalous behavior
    ]
    df = pd.DataFrame(data, columns=['logins', 'failed_attempts'])
    model = IsolationForest(contamination=0.2)
    model.fit(df)
    with open('anomaly_model.pkl', 'wb') as f:
        pickle.dump(model, f)

# Load the Isolation Forest model
def load_isolation_forest():
    try:
        with open('anomaly_model.pkl', 'rb') as f:
            model = pickle.load(f)
    except FileNotFoundError:
        train_isolation_forest()
        with open('anomaly_model.pkl', 'rb') as f:
            model = pickle.load(f)
    return model

anomaly_model = load_isolation_forest()

def detect_anomaly(logins, failed_attempts):
    features = np.array([[logins, failed_attempts]])
    return anomaly_model.predict(features)[0] == -1

def notify_admin_of_change(change_type, details):
    subject = f"Alert: {change_type}"
    body = f"The following change has occurred:\n\n{details}"
    send_email(subject, body)

def notify_admin_of_login_attempt(username, status):
    subject = f"Login Attempt: {status}"
    body = f"User {username} attempted to log in. Status: {status}"
    send_email(subject, body)

@app.route('/')
def index():
    if 'username' in session:
        return redirect(url_for('server_management'))
    else:
        return redirect(url_for('main_login'))

@app.route('/main_login', methods=['GET', 'POST'])
def main_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = next((u for u in users if u['username'] == username), None)
        if user and check_password_hash(user['password'], password):
            logins = 20
            failed_attempts = 2
            if detect_anomaly(logins, failed_attempts):
                notify_admin_of_login_attempt(username, 'Suspicious')
                flash('Suspicious login detected! Please contact support.', 'danger')
                return redirect(url_for('main_login'))

            session['username'] = username
            notify_admin_of_login_attempt(username, 'Successful')
            flash('Logged in successfully', 'success')
            return redirect(url_for('server_management'))
        else:
            notify_admin_of_login_attempt(username, 'Failed')
            flash('Login failed. Please check your username and password.', 'danger')
    return render_template('main_login.html')

@app.route('/license')
def license_agreement():
    return render_template('license_agreement.html')

@app.route('/server_management')
def server_management():
    if 'username' in session:
        return render_template('index.html', user=get_user(), servers=servers, firewall_rules=firewall_rules)
    else:
        return redirect(url_for('main_login'))

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('main_login'))

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
                notify_admin_of_change('New Server Added', f"Server Name: {server_name}, Status: {status}, IP: {ip}")
                flash(f'Server {server_name} has been added successfully', 'success')
                return redirect(url_for('server_management'))
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
                notify_admin_of_change('New Firewall Rule Added', f"Source IP: {source_ip}, Action: {action}")
                flash('Firewall rule has been added successfully', 'success')
                return redirect(url_for('server_management'))
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
                
                if server['status'] == 'Offline':
                    notify_admin_of_change('Server Status Changed', f"Server Name: {server_name}, Status: {server['status']}")
                
                flash(f'Server {server_name} status has been toggled.', 'success')
            else:
                flash('Server not found.', 'danger')
            return redirect(url_for('server_management'))
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
                
                notify_admin_of_change('Firewall Rule Action Toggled', f"Source IP: {source_ip}, Action: {rule['action']}")
                flash(f'Firewall action for {source_ip} has been toggled.', 'success')
            else:
                flash('Firewall rule not found.', 'danger')
            return redirect(url_for('server_management'))
        else:
            flash('Access denied. You do not have permission to toggle firewall action.', 'danger')
    else:
        return redirect(url_for('main_login'))

@app.route('/load_balancer_management', methods=['GET', 'POST'])
def load_balancer_management():
    if 'username' in session:
        user = get_user()
        if user and user['role'] == 'admin':
            if request.method == 'POST':
                lb_name = request.form['lb_name']
                lb_ip = request.form['lb_ip']
                lb_status = request.form['lb_status']

                new_lb = {
                    'name': lb_name,
                    'ip': lb_ip,
                    'status': lb_status
                }
                load_balancers.append(new_lb)
                notify_admin_of_change('Load Balancer Added', f"Name: {lb_name}, IP: {lb_ip}, Status: {lb_status}")
                flash(f'Load balancer {lb_name} has been added successfully', 'success')
                return redirect(url_for('load_balancer_management'))
            return render_template('load_balancer_management.html', user=user, load_balancers=load_balancers)
        else:
            flash('Access denied. You do not have permission to manage load balancers.', 'danger')
    else:
        return redirect(url_for('main_login'))

@app.route('/monitoring_dashboard')
def monitoring_dashboard():
    if 'username' in session:
        return render_template('monitoring_dashboard.html', user=get_user())
    else:
        return redirect(url_for('main_login'))

@app.route('/test_email')
def test_email():
    if 'username' in session:
        user = get_user()
        if user and user['role'] == 'admin':
            notify_admin_of_change('Test Email', 'This is a test email notification.')
            flash('Test email sent.', 'success')
            return redirect(url_for('server_management'))
        else:
            flash('Access denied.', 'danger')
    return redirect(url_for('main_login'))

if __name__ == '__main__':
    app.run(debug=True)
