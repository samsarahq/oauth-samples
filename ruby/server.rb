require 'sinatra'
require 'dotenv/load'
require 'net/http'
require 'json'
require 'securerandom'

# Set a secret key for session encryption
set :session_secret, ENV['SESSION_SECRET'] || SecureRandom.hex(32)
enable :sessions
set :port, 5000


def refresh_tokens(refresh_token)
  auth = Base64.strict_encode64("#{ENV['SAMSARA_CLIENT_ID']}:#{ENV['SAMSARA_CLIENT_SECRET']}")
  uri = URI('https://api.samsara.com/oauth2/token')
  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl = true

  request = Net::HTTP::Post.new(uri)
  request['Content-Type'] = 'application/x-www-form-urlencoded'
  request['Authorization'] = "Basic #{auth}"
  request.body = URI.encode_www_form({
    refresh_token: refresh_token,
    grant_type: 'refresh_token'
  })

  response = http.request(request)
  token_data = JSON.parse(response.body)

  # Calculate new expires_at timestamp
  expires_at = Time.now.to_i + token_data['expires_in'].to_i

  {
    'access_token' => token_data['access_token'],
    'refresh_token' => token_data['refresh_token'],
    'expires_at' => expires_at
  }
end


# Landing page with welcome message and button
get '/' do
  credentials = session[:credentials] || {}
  access_token = credentials['access_token'] || 'No access token stored locally.'

  <<~HTML
    <html>
      <body>
        <p>Access Token: <pre>#{access_token}</pre></p>
        <a href="/auth/samsara">Connect to Samsara</a><br /><br />

        <a href="/me">Test API Call</a><br>
        <a href="/auth/samsara/refresh">Refresh Access Token</a><br>
        <a href="/auth/samsara/revoke">Revoke Access Token</a><br>
      </body>
    </html>
  HTML
end

# Step 1: Redirect to Samsara's OAuth 2.0 authorization flow
get '/auth/samsara' do
  # Generate state parameter for CSRF protection
  state = SecureRandom.hex(10)
  session[:oauth_state] = state

  # Construct authorization URL
  auth_params = {
    client_id: ENV['SAMSARA_CLIENT_ID'],
    response_type: 'code',
    state: state,
    redirect_uri: 'http://localhost:5000/auth/samsara/callback'
  }

  query_string = URI.encode_www_form(auth_params)
  redirect "https://api.samsara.com/oauth2/authorize?#{query_string}"
end

# Step 2: Handle the callback from Samsara's OAuth 2.0 authorization flow
get '/auth/samsara/callback' do
  # Verify state parameter to prevent CSRF
  if params[:state] != session[:oauth_state]
    return "Invalid state parameter"
  end

  # Exchange authorization code for access token
  if params[:code]
    auth = Base64.strict_encode64("#{ENV['SAMSARA_CLIENT_ID']}:#{ENV['SAMSARA_CLIENT_SECRET']}")

    uri = URI('https://api.samsara.com/oauth2/token')
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = true

    request = Net::HTTP::Post.new(uri)
    request['Content-Type'] = 'application/x-www-form-urlencoded'
    request['Authorization'] = "Basic #{auth}"
    request.body = URI.encode_www_form({
      code: params[:code],
      grant_type: 'authorization_code'
    })

    response = http.request(request)

    if response.code == '200'
      token_data = JSON.parse(response.body)

      # Calculate expires_at timestamp
      expires_at = Time.now.to_i + token_data['expires_in'].to_i

      # Store credentials in session
      session[:credentials] = {
        'access_token' => token_data['access_token'],
        'refresh_token' => token_data['refresh_token'],
        'expires_at' => expires_at
      }

      redirect '/'
    else
      "Error obtaining access token: #{response.body}"
    end
  else
    params[:error]
  end
end

# Step 4: Use the access token to make an API call
get '/me' do
  credentials = session[:credentials]
  return "No access token stored" unless credentials

  # Check if access token is expired and refresh if needed
  if credentials['expires_at'] < Time.now.to_i
    # Refresh the token and update session
    credentials = refresh_tokens(credentials['refresh_token'])
    session[:credentials] = credentials
  end

  uri = URI('https://api.samsara.com/me')
  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl = true

  request = Net::HTTP::Get.new(uri)
  request['Authorization'] = "Bearer #{credentials['access_token']}"

  response = http.request(request)
  content_type :json
  response.body
end

# Step 5: Refresh tokens
get '/auth/samsara/refresh' do
  credentials = session[:credentials]
  return "No refresh token stored" unless credentials

  # Exchange the refresh token for new access and refresh tokens
  credentials = refresh_tokens(credentials['refresh_token'])
  session[:credentials] = credentials

  redirect '/'
end

get '/auth/samsara/revoke' do
  credentials = session[:credentials]
  return "No token to revoke" unless credentials

  auth = Base64.strict_encode64("#{ENV['SAMSARA_CLIENT_ID']}:#{ENV['SAMSARA_CLIENT_SECRET']}")
  uri = URI('https://api.samsara.com/oauth2/revoke')
  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl = true

  request = Net::HTTP::Post.new(uri)
  request['Content-Type'] = 'application/x-www-form-urlencoded'
  request['Authorization'] = "Basic #{auth}"
  request.body = URI.encode_www_form({
    token: credentials['refresh_token']
  })

  response = http.request(request)
  if response.code == '200'
    # Clear the session
    session.delete(:credentials)
  end

  redirect '/'
end