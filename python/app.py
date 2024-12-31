from flask import Flask, render_template, request, session
from dotenv import load_dotenv
import os
import secrets
import requests

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
# Add a secret key for session management
app.secret_key = secrets.token_hex(16)

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
    
    return render_template('index.html', 
                         client_id=SAMSARA_CLIENT_ID,
                         state=state)

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
        # Exchange the authorization code for an access token
        token_request_data = {
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': 'http://localhost:5000/callback'
        }
        
        # Create Basic Auth header
        auth = (SAMSARA_CLIENT_ID, SAMSARA_CLIENT_SECRET)
        
        try:
            # Use auth parameter instead of sending credentials in body
            response = requests.post(
                SAMSARA_TOKEN_URL, 
                data=token_request_data,
                auth=auth
            )
            response.raise_for_status()
            
            token_data = response.json()
            access_token = token_data.get('access_token')
            
            # TODO: Store the access token securely
            # For now, we'll just print it (don't do this in production!)
            print(f"Access Token: {access_token}")
            
            return "Successfully connected to Samsara!"
            
        except requests.exceptions.RequestException as e:
            print(f"Error exchanging code for token: {e}")
            return f"Error getting access token: {str(e)}", 400
    else:
        # Handle error cases
        error = request.args.get('error')
        error_description = request.args.get('error_description')
        return f"Authorization failed: {error} - {error_description}", 400

if __name__ == '__main__':
    app.run(debug=True)