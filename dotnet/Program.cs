using dotenv.net;
using Microsoft.Data.Sqlite;

var builder = WebApplication.CreateBuilder(args);

// Add SQLite connection
var connectionString = "Data Source=demo.db";
using (var connection = new Microsoft.Data.Sqlite.SqliteConnection(connectionString))
{
    connection.Open();

    // Drop existing demo table if it exists
    using (var command = connection.CreateCommand())
    {
        command.CommandText = "DROP TABLE IF EXISTS demo";
        command.ExecuteNonQuery();
    }

    // Create new demo table
    using (var command = connection.CreateCommand())
    {
        command.CommandText = @"
            CREATE TABLE IF NOT EXISTS demo (
                access_token TEXT,
                refresh_token TEXT
            )";
        command.ExecuteNonQuery();
    }
}

var app = builder.Build();

// Enable serving static files
app.UseStaticFiles();

// Map the root route to serve index.html
app.MapGet("/", async context =>
{
    // Get access token from database (not implemented in this example)
    var accessToken = "No access token stored locally.";
    using (var connection = new Microsoft.Data.Sqlite.SqliteConnection(connectionString))
    {
        connection.Open();
        using (var command = connection.CreateCommand())
        {
            command.CommandText = "SELECT access_token FROM demo";
            var result = command.ExecuteScalar();
            if (result != null)
            {
                accessToken = result.ToString();
            }
        }
    }

    var html = $@"
        <html>
            <body>
                <p>Access Token: <pre>{accessToken}</pre></p>
                <a href=""/auth/samsara"">Connect to Samsara</a><br /><br />

                <a href=""/me"">Test API Call</a><br>
                <a href=""/auth/samsara/refresh"">Refresh Access Token</a><br>
                <a href=""/auth/samsara/revoke"">Revoke Access Token</a><br>
            </body>
        </html>";

    await context.Response.WriteAsync(html);
});

// Load environment variables from .env file
DotEnv.Load();

var clientId = Environment.GetEnvironmentVariable("SAMSARA_CLIENT_ID");
var clientSecret = Environment.GetEnvironmentVariable("SAMSARA_CLIENT_SECRET");

if (string.IsNullOrEmpty(clientId) || string.IsNullOrEmpty(clientSecret))
{
    throw new Exception("Missing required environment variables. Please check .env file");
}

// Step 1: Redirect user to Samsara's OAuth 2.0 authorization flow
app.MapGet("/auth/samsara", async context =>
{
    // Generate random state parameter for CSRF protection
    var state = Guid.NewGuid().ToString("N");

    // Build authorization URL with required parameters
    var authUrl = new UriBuilder("https://api.samsara.com/oauth2/authorize");
    var query = System.Web.HttpUtility.ParseQueryString(string.Empty);
    query["client_id"] = clientId;
    query["response_type"] = "code";
    query["state"] = state;
    query["redirect_uri"] = "http://localhost:5000/auth/samsara/callback";
    authUrl.Query = query.ToString();

    // Redirect user to Samsara OAuth page
    context.Response.Redirect(authUrl.ToString());
});

// Step 2: OAuth callback endpoint to exchange auth code for tokens
app.MapGet("/auth/samsara/callback", async context =>
{
    var code = context.Request.Query["code"].ToString();
    var state = context.Request.Query["state"].ToString();

    // Verify state parameter matches for CSRF protection
    if (string.IsNullOrEmpty(state))
    {
        context.Response.StatusCode = 400;
        await context.Response.WriteAsync("Missing state parameter");
        return;
    }

    // Step 3: Exchange auth code for tokens
    using var client = new HttpClient();
    var tokenRequest = new FormUrlEncodedContent(new Dictionary<string, string>
    {
        ["grant_type"] = "authorization_code",
        ["code"] = code
    });

    // Add Basic Auth header
    var auth = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes($"{clientId}:{clientSecret}"));
    client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Basic", auth);

    var response = await client.PostAsync("https://api.samsara.com/oauth2/token", tokenRequest);
    var result = await response.Content.ReadAsStringAsync();

    if (!response.IsSuccessStatusCode)
    {
        context.Response.StatusCode = 400;
        await context.Response.WriteAsync($"Failed to exchange code for tokens: {result}");
        return;
    }

    // Parse token response
    var tokenResponse = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, object>>(result);
    var accessToken = tokenResponse["access_token"].ToString();
    var refreshToken = tokenResponse["refresh_token"].ToString();

    // Store tokens in database
    using (var connection = new Microsoft.Data.Sqlite.SqliteConnection(connectionString))
    {
        connection.Open();
        using (var command = connection.CreateCommand())
        {
            command.CommandText = "INSERT INTO demo (access_token, refresh_token) VALUES (@access_token, @refresh_token)";
            command.Parameters.AddWithValue("@access_token", accessToken);
            command.Parameters.AddWithValue("@refresh_token", refreshToken);
            command.ExecuteNonQuery();
        }
    }

    context.Response.Redirect("/");
});

// Step 4: Make a Test API Call with the access token
app.MapGet("/me", async context =>
{
    // Get access token from database
    var accessToken = "";
    using (var connection = new Microsoft.Data.Sqlite.SqliteConnection(connectionString))
    {
        connection.Open();
        using (var command = connection.CreateCommand())
        {
            command.CommandText = "SELECT access_token FROM demo";
            var result = command.ExecuteScalar();
            if (result != null)
            {
                accessToken = result.ToString();
            }
        }
    }

    // Make API call with access token
    using var client = new HttpClient();
    client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);
    var response = await client.GetAsync("https://api.samsara.com/me");
    var rawResponse = await response.Content.ReadAsStringAsync();
    await context.Response.WriteAsync(rawResponse);
});

// Step 5: Refresh the access token
app.MapGet("/auth/samsara/refresh", async context =>
{
    // Get refresh token from database
    var refreshToken = "";
    using (var connection = new Microsoft.Data.Sqlite.SqliteConnection(connectionString))
    {
        connection.Open();
        using (var command = connection.CreateCommand())
        {
            command.CommandText = "SELECT refresh_token FROM demo";
            var result = command.ExecuteScalar();
            if (result != null)
            {
                refreshToken = result.ToString();
            }
        }
    }

    if (string.IsNullOrEmpty(refreshToken))
    {
        await context.Response.WriteAsync("No refresh token found");
        return;
    }

    // Exchange refresh token for new tokens
    using var client = new HttpClient();
    var tokenEndpoint = "https://api.samsara.com/oauth2/token";

    // Add basic auth header
    var auth = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes($"{clientId}:{clientSecret}"));
    client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Basic", auth);

    // Prepare form data
    var formData = new Dictionary<string, string>
    {
        { "grant_type", "refresh_token" },
        { "refresh_token", refreshToken }
    };

    var response = await client.PostAsync(tokenEndpoint, new FormUrlEncodedContent(formData));
    var responseContent = await response.Content.ReadAsStringAsync();
    var tokenResponse = System.Text.Json.JsonDocument.Parse(responseContent).RootElement;

    // Check if token refresh was successful
    if (!response.IsSuccessStatusCode)
    {
        await context.Response.WriteAsync($"Failed to refresh token: {responseContent}");
        return;
    }

    var newAccessToken = tokenResponse.GetProperty("access_token").GetString();
    var newRefreshToken = tokenResponse.GetProperty("refresh_token").GetString();

    // Update tokens in database
    using (var connection = new Microsoft.Data.Sqlite.SqliteConnection(connectionString))
    {
        connection.Open();
        using (var command = connection.CreateCommand())
        {
            command.CommandText = "UPDATE demo SET access_token = @access_token, refresh_token = @refresh_token WHERE refresh_token = @old_refresh_token";
            command.Parameters.AddWithValue("@access_token", newAccessToken);
            command.Parameters.AddWithValue("@refresh_token", newRefreshToken);
            command.Parameters.AddWithValue("@old_refresh_token", refreshToken);
            command.ExecuteNonQuery();
        }
    }

    context.Response.Redirect("/");
});

// Revoke the access token
app.MapGet("/auth/samsara/revoke", async context =>
{
    // Get access token from database
    using (var connection = new Microsoft.Data.Sqlite.SqliteConnection(connectionString))
    {
        connection.Open();
        using (var command = connection.CreateCommand())
        {
            command.CommandText = "SELECT refresh_token FROM demo";
            var refreshToken = command.ExecuteScalar()?.ToString();

            if (string.IsNullOrEmpty(refreshToken))
            {
                await context.Response.WriteAsync("No refresh token found");
                return;
            }

            // Call Samsara revoke endpoint
            using var client = new HttpClient();
            var revokeEndpoint = "https://api.samsara.com/oauth2/revoke";

            // Add basic auth header
            var auth = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes($"{clientId}:{clientSecret}"));
            client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Basic", auth);

            var formData = new Dictionary<string, string>
            {
                { "token", refreshToken }
            };

            var response = await client.PostAsync(revokeEndpoint, new FormUrlEncodedContent(formData));

            // If revoke was successful, delete tokens from database
            if (response.IsSuccessStatusCode)
            {
                using (var deleteCommand = connection.CreateCommand())
                {
                    deleteCommand.CommandText = "DELETE FROM demo";
                    deleteCommand.ExecuteNonQuery();
                }
                await context.Response.WriteAsync("Token revoked successfully");
            }
            else
            {
                var responseContent = await response.Content.ReadAsStringAsync();
                await context.Response.WriteAsync($"Failed to revoke token: {responseContent}");
            }
        }
    }
});

app.Run();
