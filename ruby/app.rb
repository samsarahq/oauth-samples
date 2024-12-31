require 'sinatra'
require 'dotenv/load'
require 'faraday'
require 'securerandom'

enable :sessions

# Landing page with welcome message and button
get '/' do
  <<~HTML
    <!DOCTYPE html>
    <html>
      <head>
        <title>Samsara Integration</title>
        <style>
          body {
            font-family: Arial, sans-serif;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            height: 100vh;
            margin: 0;
          }
          .button {
            display: inline-block;
            padding: 12px 24px;
            background-color: #0077cc;
            color: white;
            text-decoration: none;
            border-radius: 4px;
            font-size: 16px;
            margin-top: 20px;
          }
          .button:hover {
            background-color: #005fa3;
          }
        </style>
      </head>
      <body>
        <h1>Welcome to Samsara Integration</h1>
        <a href="/authorize" class="button">Connect to Samsara</a>
      </body>
    </html>
  HTML
end

# Initiate OAuth flow
get '/authorize' do
  # Generate state parameter for CSRF protection
  state = SecureRandom.hex(10)
  session[:oauth_state] = state

  # Construct authorization URL
  auth_params = {
    client_id: ENV['SAMSARA_CLIENT_ID'],
    response_type: 'code',
    state: state
  }

  query_string = URI.encode_www_form(auth_params)
  redirect "https://api.samsara.com/oauth2/authorize?#{query_string}"
end

# OAuth callback endpoint
get '/callback' do
  # Verify state parameter to prevent CSRF
  if params[:state] != session[:oauth_state]
    return "Invalid state parameter"
  end

  # Exchange authorization code for access token
  if params[:code]
    response = Faraday.post('https://api.samsara.com/oauth2/token') do |req|
      req.headers['Content-Type'] = 'application/x-www-form-urlencoded'
      req.headers['Authorization'] = "Basic #{Base64.strict_encode64("#{ENV['SAMSARA_CLIENT_ID']}:#{ENV['SAMSARA_CLIENT_SECRET']}")}"
      req.body = URI.encode_www_form({
        code: params[:code],
        grant_type: 'authorization_code'
      })
    end

    if response.status == 200
      token_data = JSON.parse(response.body)
      session[:access_token] = token_data['access_token']
      session[:refresh_token] = token_data['refresh_token']
      "Successfully connected to Samsara! #{token_data['access_token']}"
    else
      "Error obtaining access token: #{response.body}"
    end
  else
    "Error: No authorization code received"
  end
end 