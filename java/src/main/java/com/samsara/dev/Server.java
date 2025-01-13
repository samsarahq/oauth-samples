package com.samsara.dev;

import static spark.Spark.*;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Base64;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import io.github.cdimascio.dotenv.Dotenv;


public class Server {
    public static void main(String[] args) {
        // Load environment variables from .env file
        Dotenv dotenv = Dotenv.load();

        // Set port to 5000 to match other examples
        port(5000);

        // Return HTML with access token and action links
        get("/", (req, res) -> {
            // Get access token from database. In practice, each user would have their own token.
            String accessToken = "No access token stored locally."; // TODO: Get from DB

            return String.format("""
                <html>
                  <body>
                    <p>Access Token: <pre>%s</pre></p>
                    <a href="/auth/samsara">Connect to Samsara</a><br /><br />

                    <a href="/me">Test API Call</a><br>
                    <a href="/auth/samsara/refresh">Refresh Access Token</a><br>
                    <a href="/auth/samsara/revoke">Revoke Access Token</a><br>
                  </body>
                </html>
            """, accessToken);
        });

        // Step 1: Redirect to Samsara OAuth 2.0 authorization URL
        get("/auth/samsara", (req, res) -> {
            String redirectUri = "http://localhost:5000/auth/samsara/callback";

            String state = java.util.UUID.randomUUID().toString();
            req.session().attribute("oauth_state", state);
            String clientId = dotenv.get("SAMSARA_CLIENT_ID");
            String clientSecret = dotenv.get("SAMSARA_CLIENT_SECRET");

            String authorizationUrl = String.format("https://api.samsara.com/oauth2/authorize?client_id=%s&response_type=code&redirect_uri=%s&state=%s", clientId, redirectUri, state);
            res.redirect(authorizationUrl);
            return "";
        });

        // Step 2: Handle Samsara OAuth 2.0 authorization callback
        get("/auth/samsara/callback", (req, res) -> {
            String code = req.queryParams("code");
            String state = req.queryParams("state");
            String storedState = req.session().attribute("oauth_state");

            if (state == null || !state.equals(storedState)) {
                res.status(400);
                return "State mismatch";
            }

            // Create HTTP client
            HttpClient client = HttpClient.newHttpClient();

            // Build request body with authorization code
            String redirectUri = "http://localhost:5000/auth/samsara/callback";
            String requestBody = String.format("grant_type=authorization_code&code=%s&redirect_uri=%s", code, redirectUri);

            // Create request with client credentials
            String clientId = dotenv.get("SAMSARA_CLIENT_ID");
            String clientSecret = dotenv.get("SAMSARA_CLIENT_SECRET");
            String credentials = clientId + ":" + clientSecret;
            String encodedCredentials = Base64.getEncoder().encodeToString(credentials.getBytes());

            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("https://api.samsara.com/oauth2/token"))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Authorization", "Basic " + encodedCredentials)
                .POST(HttpRequest.BodyPublishers.ofString(requestBody))
                .build();

            // Execute request
            try {
                HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

                if (response.statusCode() != 200) {
                    res.status(400);
                    System.out.println(response.body());
                    return "Failed to exchange code for tokens";
                }

                // Parse response JSON
                JsonObject tokens = JsonParser.parseString(response.body()).getAsJsonObject();
                String accessToken = tokens.get("access_token").getAsString();
                String refreshToken = tokens.get("refresh_token").getAsString();

                // TODO: Store tokens in database
                System.out.println("Access Token: " + accessToken);
                System.out.println("Refresh Token: " + refreshToken);

                res.redirect("/");
                return "";
            } catch (Exception e) {
                res.status(500);
                return "Error exchanging code for tokens: " + e.getMessage();
            }
        });
    }
}
