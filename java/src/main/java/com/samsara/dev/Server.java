package com.samsara.dev;

import static spark.Spark.*;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import io.github.cdimascio.dotenv.Dotenv;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

public class Server {
  public static void main(String[] args) {
    // Load environment variables from .env file
    Dotenv dotenv = Dotenv.load();

    // Set port to 5000 to match other examples
    port(5000);

    // Return HTML with access token and action links
    get("/", (req, res) -> {
      // Get access token from session
      String accessToken = "No access token stored locally.";
      String credentials = req.session().attribute("credentials");
      if (credentials != null) {
        JsonObject credentialsObj =
            JsonParser.parseString(credentials).getAsJsonObject();
        accessToken = credentialsObj.get("access_token").getAsString();
      }

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

      String authorizationUrl =
          String.format("https://api.samsara.com/oauth2/authorize?"
                            + "client_id=%s"
                            + "&response_type=code"
                            + "&redirect_uri=%s"
                            + "&state=%s",
                        clientId, redirectUri, state);
      res.redirect(authorizationUrl);
      return "";
    });

    // Step 2: Handle Samsara OAuth 2.0 authorization callback
    get("/auth/samsara/callback", (req, res) -> {
      String code = req.queryParams("code");
      String state = req.queryParams("state");
      String storedState = req.session().attribute("oauth_state");

      // Confirm the state matches the stored state to prevent CSRF attacks
      if (state == null || !state.equals(storedState)) {
        res.status(400);
        return "State mismatch";
      }

      // Create HTTP client
      HttpClient client = HttpClient.newHttpClient();
      String redirectUri = "http://localhost:5000/auth/samsara/callback";
      String requestBody =
          String.format("grant_type=authorization_code&code=%s&redirect_uri=%s",
                        code, redirectUri);

      String credentials = dotenv.get("SAMSARA_CLIENT_ID") + ":" +
                           dotenv.get("SAMSARA_CLIENT_SECRET");
      String auth = Base64.getEncoder().encodeToString(credentials.getBytes());

      // Step 3: Exchange the authorization code for access and refresh tokens
      HttpRequest request =
          HttpRequest.newBuilder()
              .uri(URI.create("https://api.samsara.com/oauth2/token"))
              .header("Content-Type", "application/x-www-form-urlencoded")
              .header("Authorization", "Basic " + auth)
              .POST(HttpRequest.BodyPublishers.ofString(requestBody))
              .build();

      try {
        HttpResponse<String> response =
            client.send(request, HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() != 200) {
          res.status(400);
          return "Failed to exchange code for tokens";
        }

        JsonObject tokens =
            JsonParser.parseString(response.body()).getAsJsonObject();
        String accessToken = tokens.get("access_token").getAsString();
        String refreshToken = tokens.get("refresh_token").getAsString();
        long expiresIn = tokens.get("expires_in").getAsLong();
        long expiresAt = System.currentTimeMillis() / 1000; // + expiresIn;

        // Store tokens in session
        JsonObject credentialsObj = new JsonObject();
        credentialsObj.addProperty("access_token", accessToken);
        credentialsObj.addProperty("refresh_token", refreshToken);
        credentialsObj.addProperty("expires_at", expiresAt);
        req.session().attribute("credentials", credentialsObj.toString());

        res.redirect("/");
        return "";
      } catch (Exception e) {
        res.status(500);
        return "Error exchanging code for tokens: " + e.getMessage();
      }
    });

    // Step 4: Use the access token to make an API call
    get("/me", (req, res) -> {
      String credentials = req.session().attribute("credentials");
      if (credentials == null) {
        return "No credentials found in session";
      }

      JsonObject credentialsObj =
          JsonParser.parseString(credentials).getAsJsonObject();
      String accessToken = credentialsObj.get("access_token").getAsString();

      // If the tokens are expired, refresh them
      if (credentialsObj.get("expires_at").getAsLong() <
          System.currentTimeMillis() / 1000) {
        try {
          JsonObject newCredentials =
              refreshTokens(credentialsObj.get("refresh_token").getAsString(),
                            dotenv.get("SAMSARA_CLIENT_ID"),
                            dotenv.get("SAMSARA_CLIENT_SECRET"));
          req.session().attribute("credentials", newCredentials.toString());
          accessToken = newCredentials.get("access_token").getAsString();
        } catch (Exception e) {
          return "Error refreshing tokens: " + e.getMessage();
        }
      }

      // Make API call to /me endpoint
      HttpClient client = HttpClient.newHttpClient();
      HttpRequest request =
          HttpRequest.newBuilder()
              .uri(URI.create("https://api.samsara.com/me"))
              .header("Authorization", "Bearer " + accessToken)
              .GET()
              .build();

      HttpResponse<String> response =
          client.send(request, HttpResponse.BodyHandlers.ofString());

      if (response.statusCode() != 200) {
        return "API call failed with status code: " + response.statusCode();
      }

      res.type("application/json");
      return response.body();
    });

    // Step 5: Refresh the access token
    get("/auth/samsara/refresh", (req, res) -> {
      String credentials = req.session().attribute("credentials");
      if (credentials == null) {
        return "No credentials found in session";
      }

      JsonObject credentialsObj =
          JsonParser.parseString(credentials).getAsJsonObject();
      String refreshToken = credentialsObj.get("refresh_token").getAsString();

      try {
        // Refresh the tokens
        JsonObject newCredentials =
            refreshTokens(refreshToken, dotenv.get("SAMSARA_CLIENT_ID"),
                          dotenv.get("SAMSARA_CLIENT_SECRET"));

        // Store the new credentials in the session
        req.session().attribute("credentials", newCredentials.toString());
      } catch (Exception e) {
        return "Error refreshing tokens: " + e.getMessage();
      }

      res.redirect("/");
      return null;
    });

    // Revoke the access token
    get("/auth/samsara/revoke", (req, res) -> {
      String credentials = req.session().attribute("credentials");
      if (credentials == null) {
        return "No credentials found in session";
      }

      JsonObject credentialsObj =
          JsonParser.parseString(credentials).getAsJsonObject();
      String refreshToken = credentialsObj.get("refresh_token").getAsString();

      // Create HTTP client
      HttpClient client = HttpClient.newHttpClient();

      // Create auth header
      String auth = dotenv.get("SAMSARA_CLIENT_ID") + ":" +
                    dotenv.get("SAMSARA_CLIENT_SECRET");
      String encodedAuth = Base64.getEncoder().encodeToString(auth.getBytes());

      // Build request body
      String requestBody = "token=" + refreshToken;

      // Create request
      HttpRequest request =
          HttpRequest.newBuilder()
              .uri(URI.create("https://api.samsara.com/oauth2/revoke"))
              .header("Content-Type", "application/x-www-form-urlencoded")
              .header("Authorization", "Basic " + encodedAuth)
              .POST(HttpRequest.BodyPublishers.ofString(requestBody))
              .build();

      HttpResponse<String> response =
          client.send(request, HttpResponse.BodyHandlers.ofString());

      if (response.statusCode() == 200) {
        // Remove credentials from session
        req.session().removeAttribute("credentials");
        res.redirect("/");
        return null;
      } else {
        return "Failed to revoke access token and refresh token";
      }
    });
  }

  private static JsonObject refreshTokens(String refreshToken, String clientId,
                                          String clientSecret)
      throws Exception {

    // Create auth header with client credentials
    String auth = clientId + ":" + clientSecret;
    String encodedAuth = Base64.getEncoder().encodeToString(auth.getBytes());

    // Build request body
    Map<String, String> formData = new HashMap<>();
    formData.put("grant_type", "refresh_token");
    formData.put("refresh_token", refreshToken);

    String requestBody = formData.entrySet()
                             .stream()
                             .map(e -> e.getKey() + "=" + e.getValue())
                             .collect(Collectors.joining("&"));

    // Make token refresh request
    HttpClient client = HttpClient.newHttpClient();
    HttpRequest request =
        HttpRequest.newBuilder()
            .uri(URI.create("https://api.samsara.com/oauth2/token"))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .header("Authorization", "Basic " + encodedAuth)
            .POST(HttpRequest.BodyPublishers.ofString(requestBody))
            .build();

    try {
      HttpResponse<String> response =
          client.send(request, HttpResponse.BodyHandlers.ofString());

      if (response.statusCode() != 200) {
        throw new Exception("Token refresh failed with status code: " +
                            response.statusCode());
      }

      // Parse response JSON
      JsonObject tokenData =
          JsonParser.parseString(response.body()).getAsJsonObject();

      if (!tokenData.has("access_token")) {
        throw new Exception("Failed to refresh token");
      }

      String newAccessToken = tokenData.get("access_token").getAsString();
      String newRefreshToken = tokenData.get("refresh_token").getAsString();
      long expiresIn = tokenData.get("expires_in").getAsLong();
      long expiresAt = System.currentTimeMillis() / 1000 + expiresIn;

      // Store tokens in session
      JsonObject credentialsObj = new JsonObject();
      credentialsObj.addProperty("access_token", newAccessToken);
      credentialsObj.addProperty("refresh_token", newRefreshToken);
      credentialsObj.addProperty("expires_at", expiresAt);
      return credentialsObj;
    } catch (Exception e) {
      throw new Exception("Error refreshing tokens: " + e.getMessage());
    }
  }
}
