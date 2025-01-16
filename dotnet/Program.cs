using dotenv.net;
using Microsoft.AspNetCore.Session;
using System.Text.Json;

// Load environment variables from .env file
DotEnv.Load();

var clientId = Environment.GetEnvironmentVariable("SAMSARA_CLIENT_ID");
var clientSecret = Environment.GetEnvironmentVariable("SAMSARA_CLIENT_SECRET");

if (string.IsNullOrEmpty(clientId) || string.IsNullOrEmpty(clientSecret))
{
    throw new Exception("Missing required environment variables. Please check .env file");
}

var builder = WebApplication.CreateBuilder(args);

// Add session support
builder.Services.AddDistributedMemoryCache();
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(30);
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
});

var app = builder.Build();

// Enable serving static files and session
app.UseStaticFiles();
app.UseSession();

// Helper function to refresh access token and return updated credentials
static async Task<Dictionary<string, string>> RefreshAccessTokenAsync(string refreshToken, string clientId, string clientSecret)
{
    using var client = new HttpClient();
    var tokenEndpoint = "https://api.samsara.com/oauth2/token";

    // Add basic auth header
    var auth = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes($"{clientId}:{clientSecret}"));
    client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Basic", auth);

    var tokenRequest = new Dictionary<string, string>
    {
        { "refresh_token", refreshToken },
        { "grant_type", "refresh_token" }
    };

    var tokenResponse = await client.PostAsync(tokenEndpoint, new FormUrlEncodedContent(tokenRequest));
    var tokenContent = await tokenResponse.Content.ReadAsStringAsync();

    if (!tokenResponse.IsSuccessStatusCode)
    {
        throw new Exception($"Failed to refresh token: {tokenContent}");
    }

    var tokenData = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(tokenContent);
    var expiresAt = DateTimeOffset.UtcNow.AddSeconds(tokenData["expires_in"].GetInt32()).ToUnixTimeSeconds();

    return new Dictionary<string, string>
    {
        ["access_token"] = tokenData["access_token"].GetString(),
        ["refresh_token"] = tokenData["refresh_token"].GetString(),
        ["expires_at"] = expiresAt.ToString()
    };
}


app.MapGet("/", async context =>
{
    // Get access token from session
    var credentials = context.Session.GetString("credentials");
    var accessToken = "No access token stored locally.";
    if (!string.IsNullOrEmpty(credentials))
    {
        var credentialsObj = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, string>>(credentials);
        accessToken = credentialsObj["access_token"];
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

    // Parse token response using JsonElement to handle numeric values correctly
    var tokenResponse = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(result);
    var accessToken = tokenResponse["access_token"].GetString();
    var refreshToken = tokenResponse["refresh_token"].GetString();
    var expiresIn = tokenResponse["expires_in"].GetInt32();
    var expiresAt = DateTimeOffset.UtcNow.AddSeconds(expiresIn).ToUnixTimeSeconds();

    // Store tokens in session
    var credentials = new Dictionary<string, string>
    {
        ["access_token"] = accessToken,
        ["refresh_token"] = refreshToken,
        ["expires_at"] = expiresAt.ToString()
    };

    context.Session.SetString("credentials", System.Text.Json.JsonSerializer.Serialize(credentials));
    context.Response.Redirect("/");
});

// Step 4: Make a Test API Call with the access token
app.MapGet("/me", async context =>
{
    // Get access token from session
    var credentials = context.Session.GetString("credentials");
    if (string.IsNullOrEmpty(credentials))
    {
        context.Response.StatusCode = 401;
        await context.Response.WriteAsync("No credentials found");
        return;
    }

    var credentialsObj = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, string>>(credentials);
    var accessToken = credentialsObj["access_token"];

    // If the access token is expired, refresh it
    if (DateTimeOffset.UtcNow.ToUnixTimeSeconds() > Convert.ToInt64(credentialsObj["expires_at"]))
    {
        var refreshedCredentials = await RefreshAccessTokenAsync(credentialsObj["refresh_token"], clientId, clientSecret);
        context.Session.SetString("credentials", System.Text.Json.JsonSerializer.Serialize(refreshedCredentials));
        accessToken = refreshedCredentials["access_token"];
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
    // Get refresh token from session
    var credentials = context.Session.GetString("credentials");
    if (string.IsNullOrEmpty(credentials))
    {
        await context.Response.WriteAsync("No credentials found");
        return;
    }

    var credentialsObj = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, string>>(credentials);
    var refreshToken = credentialsObj["refresh_token"];

    var refreshedCredentials = await RefreshAccessTokenAsync(refreshToken, clientId, clientSecret);
    context.Session.SetString("credentials", System.Text.Json.JsonSerializer.Serialize(refreshedCredentials));

    context.Response.Redirect("/");
});

// Revoke the access token
app.MapGet("/auth/samsara/revoke", async context =>
{
    // Get refresh token from session
    var credentials = context.Session.GetString("credentials");
    if (string.IsNullOrEmpty(credentials))
    {
        await context.Response.WriteAsync("No credentials found");
        return;
    }

    var credentialsObj = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, string>>(credentials);
    var refreshToken = credentialsObj["refresh_token"];

    // Call Samsara revoke endpoint
    using var client = new HttpClient();
    var revokeEndpoint = "https://api.samsara.com/oauth2/revoke";

    // Add basic auth header
    var auth = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes($"{clientId}:{clientSecret}"));
    client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Basic", auth);

    var revokeRequest = new Dictionary<string, string>
    {
        { "token", refreshToken }
    };

    var revokeResponse = await client.PostAsync(revokeEndpoint, new FormUrlEncodedContent(revokeRequest));

    // If revoke was successful, remove credentials from session
    if (revokeResponse.IsSuccessStatusCode)
    {
        context.Session.Remove("credentials");
        await context.Response.WriteAsync("Token revoked successfully");
    }
    else
    {
        var revokeResponseContent = await revokeResponse.Content.ReadAsStringAsync();
        await context.Response.WriteAsync($"Failed to revoke token: {revokeResponseContent}");
    }
});

app.Run();
