using dotenv.net;

var builder = WebApplication.CreateBuilder(args);

var app = builder.Build();

// Enable serving static files
app.UseStaticFiles();

// Map the root route to serve index.html
app.MapGet("/", async context =>
{
    await context.Response.SendFileAsync("wwwroot/index.html");
});

// Add DotEnv configuration
DotEnv.Load();

// Access environment variables
var clientId = Environment.GetEnvironmentVariable("SAMSARA_CLIENT_ID");
var clientSecret = Environment.GetEnvironmentVariable("SAMSARA_CLIENT_SECRET");

// Verify environment variables are set
if (string.IsNullOrEmpty(clientId) || string.IsNullOrEmpty(clientSecret))
{
    throw new Exception("Missing required environment variables. Please check .env file");
}

// OAuth authorization endpoint
app.MapGet("/authorize", async context =>
{
    // Generate random state parameter for CSRF protection
    var state = Guid.NewGuid().ToString("N");

    // Build authorization URL with required parameters
    var authUrl = new UriBuilder("https://api.samsara.com/oauth2/authorize");
    var query = System.Web.HttpUtility.ParseQueryString(string.Empty);
    query["client_id"] = clientId;
    query["response_type"] = "code";
    query["state"] = state;
    authUrl.Query = query.ToString();

    // Redirect user to Samsara OAuth page
    context.Response.Redirect(authUrl.ToString());
});

// OAuth callback endpoint to exchange auth code for tokens
app.MapGet("/callback", async context =>
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

    // Access environment variables
    var clientId = Environment.GetEnvironmentVariable("SAMSARA_CLIENT_ID");
    var clientSecret = Environment.GetEnvironmentVariable("SAMSARA_CLIENT_SECRET");

    // Verify environment variables are set
    if (string.IsNullOrEmpty(clientId) || string.IsNullOrEmpty(clientSecret))
    {
        throw new Exception("Missing required environment variables. Please check .env file");
    }

    Console.WriteLine($"Client ID: {clientId}");
    Console.WriteLine($"Client Secret: {clientSecret}");

    // Exchange auth code for tokens
    using var client = new HttpClient();
    var tokenRequest = new FormUrlEncodedContent(new Dictionary<string, string>
    {
        ["grant_type"] = "authorization_code",
        ["client_id"] = clientId,
        ["client_secret"] = clientSecret,
        ["code"] = code
    });

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
    var expiresIn = tokenResponse["expires_in"].ToString();

    // Display tokens (in practice you would securely store these)
    await context.Response.WriteAsync($"""
        Access Token: {accessToken}
        Refresh Token: {refreshToken} 
        Expires In: {expiresIn} seconds
        """);
});



app.Run();
