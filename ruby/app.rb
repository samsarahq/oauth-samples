require 'byebug'
require 'sinatra'
require 'dotenv/load'
require 'net/http'
require 'json'
require 'securerandom'
require 'sqlite3'
require 'base64'

# Set a secret key for session encryption
set :session_secret, ENV['SESSION_SECRET'] || SecureRandom.hex(32)
enable :sessions
set :port, 5000

# Landing page with welcome message and button
get '/' do
  db = get_db
  result = db.execute('SELECT access_token, refresh_token FROM demo').first
  access_token = 'No access token stored locally.'
  if result
    access_token = result['access_token']
  end

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

    # Step 3: Exchange the authorization code for an access token
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
      db = get_db
      db.execute('INSERT INTO demo (access_token, refresh_token) VALUES (?, ?)', [token_data['access_token'], token_data['refresh_token']])
      "Successfully connected to Samsara! #{token_data['access_token']}"
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
  db = get_db
  result = db.execute('SELECT access_token FROM demo').first
  access_token = result['access_token']

  uri = URI('https://api.samsara.com/me')
  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl = true

  request = Net::HTTP::Get.new(uri)
  request['Authorization'] = "Bearer #{access_token}"

  response = http.request(request)
  content_type :json
  response.body
end

# Step 5: Refresh tokens when they expire.
get '/auth/samsara/refresh' do
  db = get_db
  result = db.execute('SELECT refresh_token FROM demo').first
  refresh_token = result['refresh_token']

  # Exchange the refresh token for new access and refresh tokens
  auth = Base64.strict_encode64("#{ENV['SAMSARA_CLIENT_ID']}:#{ENV['SAMSARA_CLIENT_SECRET']}")
  uri = URI('https://api.samsara.com/oauth2/token')
  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl = true

  request = Net::HTTP::Post.new(uri)
  request['Content-Type'] = 'application/x-www-form-urlencoded'
  request['Authorization'] = "Basic #{auth}"
  request.body = URI.encode_www_form({
    refresh_token: refresh_token,
    grant_type: 'refresh_token',
    redirect_uri: 'http://localhost:5000/auth/samsara/callback'
  })

  response = http.request(request)
  token_data = JSON.parse(response.body)

  db = get_db
  new_access_token = token_data['access_token']
  new_refresh_token = token_data['refresh_token']
  db.execute('UPDATE demo SET access_token = ?, refresh_token = ? WHERE refresh_token = ?', [new_access_token, new_refresh_token, refresh_token])

  "Successfully refreshed access token: #{new_access_token}"
end

get '/auth/samsara/revoke' do
  db = get_db
  result = db.execute('SELECT refresh_token FROM demo').first
  refresh_token = result['refresh_token']

  auth = Base64.strict_encode64("#{ENV['SAMSARA_CLIENT_ID']}:#{ENV['SAMSARA_CLIENT_SECRET']}")
  uri = URI('https://api.samsara.com/oauth2/revoke')
  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl = true

  request = Net::HTTP::Post.new(uri)
  request['Content-Type'] = 'application/x-www-form-urlencoded'
  request['Authorization'] = "Basic #{auth}"
  request.body = URI.encode_www_form({
    token: refresh_token
  })

  response = http.request(request)
  if response.code == '200'
    db = get_db
    db.execute('DELETE FROM demo')

    "Successfully revoked access token"
  else
    "Error revoking access token: #{response.body}"
  end

  redirect '/'
end

# Helper method to get database connection
def get_db
  @db ||= SQLite3::Database.new('demo.db')
  @db.results_as_hash = true
  @db
end

# Initialize database schema
def init_db
  db = get_db
  db.execute('DROP TABLE IF EXISTS demo;')
  db.execute <<-SQL
    CREATE TABLE IF NOT EXISTS demo (
      access_token TEXT,
      refresh_token TEXT
    );
  SQL
end

# Initialize database on startup
init_db