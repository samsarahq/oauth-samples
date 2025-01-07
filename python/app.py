from flask import Flask, render_template, request, session, redirect, url_for, g
from dotenv import load_dotenv
import os
import secrets
import requests
import base64
import sqlite3

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
# Add a secret key for session management
app.secret_key = secrets.token_hex(16)

def get_db():
    """Create a new database connection for each request"""
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect('demo.db')
        db.row_factory = sqlite3.Row
    return db

def init_db():
    """Initialize the database schema"""
    with app.app_context():
        db = get_db()
        c = db.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS demo (
            access_token TEXT,
            refresh_token TEXT
        )''')
        db.commit()

@app.teardown_appcontext
def close_connection(exception):
    """Close database connection when app context ends"""
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# Get environment variables
SAMSARA_CLIENT_ID = os.getenv('SAMSARA_CLIENT_ID')
SAMSARA_CLIENT_SECRET = os.getenv('SAMSARA_CLIENT_SECRET')
SAMSARA_TOKEN_URL = 'https://api.samsara.com/oauth2/token'

@app.route('/')
def home():
    # Generate a random state parameter for CSRF protection
    state = secrets.token_urlsafe(16)
    # Store state in session for verification
    session['oauth_state'] = state

    # Get the access token and refresh token from the database
    db = get_db()
    c = db.cursor()
    c.execute('SELECT access_token, refresh_token FROM demo')
    result = c.fetchone()
    access_token = result['access_token'] if result else None
    refresh_token = result['refresh_token'] if result else None

    return render_template(
        'index.html',
        client_id=SAMSARA_CLIENT_ID,
        state=state,
        access_token=access_token,
        refresh_token=refresh_token
    )

@app.route('/callback')
def callback():
    # Get the authorization code and state from the request
    code = request.args.get('code')
    state = request.args.get('state')

    # Verify state to prevent CSRF attacks
    stored_state = session.get('oauth_state')
    if not state or state != stored_state:
        return 'Invalid state parameter', 400

    # Clear the state from session
    session.pop('oauth_state', None)

    if code:
        try:
            # Use auth parameter instead of sending credentials in body
            response = requests.post(
                SAMSARA_TOKEN_URL,
                data={
                    'grant_type': 'authorization_code',
                    'code': code,
                },
                auth=(SAMSARA_CLIENT_ID, SAMSARA_CLIENT_SECRET)
            )
            response.raise_for_status()

            token_data = response.json()
            access_token = token_data.get('access_token')
            refresh_token = token_data.get('refresh_token')

            # Store the access token and refresh token in the database
            db = get_db()
            c = db.cursor()
            c.execute('INSERT INTO demo (access_token, refresh_token) VALUES (?, ?)',
                     (access_token, refresh_token))
            db.commit()

            print(token_data)
            print(f"Access Token: {access_token}")

            # Redirect to home page after successful token exchange
            return redirect(url_for('home'))

        except requests.exceptions.RequestException as e:
            print(f"Error exchanging code for token: {e}")
            return f"Error getting access token: {str(e)}", 400
    else:
        # Handle error cases
        error = request.args.get('error')
        error_description = request.args.get('error_description')
        return f"Authorization failed: {error} - {error_description}", 400

@app.route('/revoke')
def revoke():
    db = get_db()
    c = db.cursor()
    c.execute('SELECT access_token, refresh_token FROM demo')
    result = c.fetchone()

    if result:
        access_token = result['access_token']

        # Delete tokens from database
        c.execute('DELETE FROM demo')
        db.commit()

        revoke_response = requests.post(
            'https://api.samsara.com/oauth2/revoke',
            data={'token': access_token},
            auth=(SAMSARA_CLIENT_ID, SAMSARA_CLIENT_SECRET)
        )

        if revoke_response.status_code == 200:
            return "Access token revoked successfully"
        else:
            return "Failed to revoke access token", 400

    return "Access token not found", 404

@app.route('/vehicles')
def vehicles():
    db = get_db()
    c = db.cursor()
    c.execute('SELECT access_token, refresh_token FROM demo')
    result = c.fetchone()
    access_token = result['access_token']
    refresh_token = result['refresh_token']

    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json'
    }

    response = requests.get('https://api.samsara.com/fleet/vehicles', headers=headers)
    response.raise_for_status()
    vehicles = response.json()
    print(vehicles)

    return render_template('vehicles.html', vehicles=vehicles['data'])


if __name__ == '__main__':
    init_db()
    app.run(debug=True)