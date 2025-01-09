import os
import secrets
import requests
import sqlite3

from flask import Flask, request, session, redirect, url_for, g
from urllib.parse import urlencode
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)

# Add a secret key for session management
app.secret_key = secrets.token_hex(16)

SAMSARA_CLIENT_ID = os.getenv('SAMSARA_CLIENT_ID')
SAMSARA_CLIENT_SECRET = os.getenv('SAMSARA_CLIENT_SECRET')


@app.get('/')
def home():
    # Get the access token and refresh token from the database. In practice,
    # each user in the Marketplace application would have their own access token
    # and refresh token stored along side the user or organization they are
    # associated with.
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT access_token, refresh_token FROM demo') # Filtered by the current user's account ID
    result = cursor.fetchone()

    if result:
        access_token = result['access_token']
    else:
        access_token = "No access token stored locally."

    return '''
      <html>
        <body>
          <p>Access Token: <pre>{access_token}</pre></p>
          <a href="/auth/samsara">Connect to Samsara</a><br /><br />

          <a href="/me">Test API Call</a><br>
          <a href="/auth/revoke">Revoke Access Token</a><br>
          <a href="/auth/refresh">Refresh Access Token</a><br>

        </body>
      </html>
    '''.format(access_token=access_token)


# Step 1: Redirect to Samsara's OAuth 2.0 authorization flow
@app.get("/auth/samsara")
def auth_samsara():
    # Generate a random state parameter for CSRF protection
    state = secrets.token_urlsafe(16)

    # Store state in session for verification
    session['oauth_state'] = state

    params = {
        'client_id': SAMSARA_CLIENT_ID,
        'state': state,
        'response_type': 'code',
        'redirect_uri': 'http://localhost:5000/auth/samsara/callback'
    }

    return redirect(f"https://api.samsara.com/oauth2/authorize?" + urlencode(params))


# Step 2: Handle the callback from Samsara's OAuth 2.0 authorization flow
@app.route('/auth/samsara/callback')
def callback():
    # Get the authorization code and state from the query params.
    code = request.args.get('code')
    state = request.args.get('state')

    # Verify state to prevent CSRF attacks
    stored_state = session.get('oauth_state')
    if not state or state != stored_state:
        return 'Invalid state parameter', 400

    # Clear the state from session
    session.pop('oauth_state', None)

    if code:
        # Step 3: Exchange the authorization code for an access token
        try:
            response = requests.post(
                'https://api.samsara.com/oauth2/token',
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

            # Store the access token and refresh token in the database. Store these in a secure location in a production app.
            db = get_db()
            cursor = db.cursor()
            cursor.execute('INSERT INTO demo (access_token, refresh_token) VALUES (?, ?)', (access_token, refresh_token)) # Along side the current user's account ID
            db.commit()

            return redirect(url_for('home'))
        except requests.exceptions.RequestException as e:
            print(f"Error exchanging code for token: {e}")
            return f"Error getting access token: {str(e)}", 400
    else:
        # Handle error cases
        error = request.args.get('error')
        error_description = request.args.get('error_description')
        return f"Authorization failed: {error} - {error_description}", 400


# Step 5: Refresh tokens when they expire.
@app.get('/auth/refresh')
def refresh():
    # Get the access token and refresh token from the database
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT refresh_token FROM demo')
    result = cursor.fetchone()
    refresh_token = result['refresh_token']

    # Exchange the refresh token for new access and refresh tokens
    response = requests.post(
        'https://api.samsara.com/oauth2/token',
        data={
            'grant_type': 'refresh_token',
            'refresh_token': refresh_token
        },
        auth=(SAMSARA_CLIENT_ID, SAMSARA_CLIENT_SECRET)
    )

    response.raise_for_status()
    token_data = response.json()
    access_token = token_data.get('access_token')
    refresh_token = token_data.get('refresh_token')

    # Store the new access token and refresh token in the database
    cursor.execute('UPDATE demo SET access_token = ?, refresh_token = ? WHERE refresh_token = ?', (access_token, refresh_token, refresh_token))
    db.commit()

    return redirect(url_for('home'))


@app.get('/auth/revoke')
def revoke():
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT refresh_token FROM demo')
    result = cursor.fetchone()

    if result:
        refresh_token = result['refresh_token']

        revoke_response = requests.post(
            'https://api.samsara.com/oauth2/revoke',
            data={'token': refresh_token},
            auth=(SAMSARA_CLIENT_ID, SAMSARA_CLIENT_SECRET)
        )

        if revoke_response.status_code == 200:
            # Delete tokens from database
            cursor.execute('DELETE FROM demo WHERE refresh_token = ?', (refresh_token,))
            db.commit()

            return "Access token and refresh token revoked successfully"
        else:
            return "Failed to revoke access token and refresh token", 400

    return "Refresh token not found", 404


# Step 4: Use the access token to make an API call
@app.get('/me')
def me():
    """Example showing how to use the access token to make an API call."""

    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT access_token FROM demo')
    result = cursor.fetchone()
    access_token = result['access_token']

    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json'
    }

    response = requests.get('https://api.samsara.com/me', headers=headers)
    response.raise_for_status()

    # If the access token is expired, try refreshing it and then making the API call again.

    return response.json()


def get_db():
    """Create a new database connection for each request"""
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect('demo.db')
        db.row_factory = sqlite3.Row
    return db


def init_db():
    """Initialize the example database schema

    In practice, each user in the Marketplace application would have their own
    access token and refresh token stored along side the user or organization
    they are associated with.
    """

    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS demo (
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


if __name__ == '__main__':
    init_db()
    app.run(debug=True)