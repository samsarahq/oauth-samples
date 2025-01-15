import os
import time
import secrets
import requests

from datetime import datetime, timedelta
from flask import Flask, request, session, redirect
from urllib.parse import urlencode
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)

# Add a secret key for session management
app.secret_key = secrets.token_hex(16)

SAMSARA_CLIENT_ID = os.getenv('SAMSARA_CLIENT_ID')
SAMSARA_CLIENT_SECRET = os.getenv('SAMSARA_CLIENT_SECRET')


def refresh_access_token(refresh_token):
    # Use the refresh token to get new access token and refresh token
    response = requests.post(
        'https://api.samsara.com/oauth2/token',
        data={
            'grant_type': 'refresh_token',
            'refresh_token': refresh_token
        },
        auth=(SAMSARA_CLIENT_ID, SAMSARA_CLIENT_SECRET)
    )

    token_data = response.json()

    # Check if token refresh was successful
    if 'access_token' not in token_data:
        raise Exception(f"Failed to refresh token: {token_data.get('error', 'Unknown error')} - {token_data.get('error_description', 'No error description provided')}")

    access_token = token_data.get('access_token')
    new_refresh_token = token_data.get('refresh_token')
    expires_at = time.time() + token_data.get('expires_in')

    # Store the new tokens in the session
    return {
        'access_token': access_token,
        'refresh_token': new_refresh_token,
        'expires_at': expires_at
    }


@app.get('/')
def home():
    print(session)

    # Get the access token and expiration timestamp from the session
    credentials = session.get('credentials', {})
    access_token = credentials.get('access_token', "No access token stored locally.")
    expires_at = credentials.get('expires_at', "No expiration stored locally.")

    return '''
      <html>
        <body>
          <p>Access Token: <pre>{access_token}</pre></p>
          <p>Expires At: <pre>{expires_at}</pre></p>
          <a href="/auth/samsara">Connect to Samsara</a><br /><br />

          <a href="/me">Test API Call</a><br>
          <a href="/auth/samsara/refresh">Refresh Access Token</a><br>
          <a href="/auth/samsara/revoke">Revoke Access Token</a><br>
        </body>
      </html>
    '''.format(access_token=access_token, expires_at=expires_at)


# Step 1: Redirect to Samsara's OAuth 2.0 authorization flow
@app.get("/auth/samsara")
def auth_samsara():
    # Generate a random state parameter for CSRF protection
    state = secrets.token_urlsafe(16)

    # Store state in session for CSRF check in step 2.
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
    # Read the authorization code and state from the query params.
    code = request.args.get('code')
    state = request.args.get('state')

    # Verify state to prevent CSRF attacks
    stored_state = session.get('oauth_state')
    if not state or state != stored_state:
        return 'Invalid state parameter', 400

    # Clear the state from session
    session.pop('oauth_state', None)

    if not code:
        # Handle error cases
        error = request.args.get('error')
        error_description = request.args.get('error_description')
        return f"Authorization failed: {error} - {error_description}", 400

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

        token_data = response.json()
        access_token = token_data.get('access_token')
        refresh_token = token_data.get('refresh_token')
        expires_at = time.time() + token_data.get('expires_in')

        # Store the tokens in the session
        session['credentials'] = {
            'access_token': access_token,
            'refresh_token': refresh_token,
            'expires_at': expires_at
        }

        return redirect("/")
    except requests.exceptions.RequestException as e:
        return f"Error getting access token: {str(e)}", 400


# Step 4: Use the access token to make an API call
@app.get('/me')
def me():
    """Example showing how to use the access token to make an API call."""

    credentials = session.get('credentials', {})
    access_token = credentials.get('access_token')
    expires_at = credentials.get('expires_at')

    # If the access token is expired, refresh it. Only refresh access tokens as
    # needed for API calls to avoid unnecessary refresh calls. Build a pattern
    # to check if a token is expired right before making an API call and if so,
    # then refresh it.
    if not expires_at or expires_at <= time.time():
        try:
            credentials = refresh_access_token(credentials.get('refresh_token'))
            session['credentials'] = credentials
            access_token = credentials.get('access_token')
        except Exception as e:
            return f"Error refreshing access token: {str(e)}", 400

    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json'
    }

    response = requests.get('https://api.samsara.com/me', headers=headers)
    response.raise_for_status()

    return response.json()


# Step 5: Refresh tokens when they expire.
@app.get('/auth/samsara/refresh')
def refresh():
    # Get the refresh token from the session
    credentials = session.get('credentials', {})
    refresh_token = credentials.get('refresh_token')

    # Refresh the access token
    credentials = refresh_access_token(refresh_token)

    # Store the new tokens in the session
    session['credentials'] = credentials

    return redirect("/")


@app.get('/auth/samsara/revoke')
def revoke():
    """Enable users to disconnect your Marketplace app from their Samsara account."""

    credentials = session.get('credentials', {})
    refresh_token = credentials.get('refresh_token')

    if refresh_token:
        revoke_response = requests.post(
            'https://api.samsara.com/oauth2/revoke',
            data={'token': refresh_token},
            auth=(SAMSARA_CLIENT_ID, SAMSARA_CLIENT_SECRET)
        )

        if revoke_response.status_code == 200:
            # Clear credentials from session
            session.pop('credentials', None)
            return "Access token and refresh token revoked successfully <a href='/'>Start over</a>"
        else:
            return "Failed to revoke access token and refresh token <a href='/'>Start over</a>", revoke_response.status_code

    return "Refresh token not found <a href='/'>Start over</a>"


if __name__ == '__main__':
    app.run(debug=True)