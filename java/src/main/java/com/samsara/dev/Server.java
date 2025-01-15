package com.samsara.dev;

import static spark.Spark.*;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import io.github.cdimascio.dotenv.Dotenv;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.sql.*;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

public class Server {
  public static void main(String[] args) {
    // Load environment variables from .env file
    Dotenv dotenv = Dotenv.load();

    // Initialize SQLite database
    String databaseConnectionString = "jdbc:sqlite:demo.db";
    try {
      // Create database connection
      Class.forName("org.sqlite.JDBC");
      try (var conn =
               java.sql.DriverManager.getConnection(databaseConnectionString)) {
        // Drop table if exists and create new one
        try (var stmt = conn.createStatement()) {
          stmt.execute("DROP TABLE IF EXISTS demo");
          stmt.execute("""
              CREATE TABLE IF NOT EXISTS demo (
                  access_token TEXT,
                  refresh_token TEXT
              )
          """);
        }
      }
    } catch (Exception e) {
      System.err.println("Database initialization failed: " + e.getMessage());
      System.exit(1);
    }

    // Set port to 5000 to match other examples
    port(5000);

    // Return HTML with access token and action links
    get("/", (req, res) -> {
      // Get access token from database. In practice, each of our shared
      // customers would have their own tokens.
      String accessToken = "No access token stored locally.";

      try (var conn = DriverManager.getConnection(databaseConnectionString)) {
        try (var stmt = conn.createStatement()) {
          var rs = stmt.executeQuery("SELECT access_token FROM demo");
          if (rs.next()) {
            accessToken = rs.getString("access_token");
          }
        }
      } catch (SQLException e) {
        System.err.println("Error reading access token: " + e.getMessage());
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
          System.out.println(response.body());
          return "Failed to exchange code for tokens";
        }

        JsonObject tokens =
            JsonParser.parseString(response.body()).getAsJsonObject();
        String accessToken = tokens.get("access_token").getAsString();
        String refreshToken = tokens.get("refresh_token").getAsString();

        // Store tokens in database
        try (Connection conn =
                 DriverManager.getConnection(databaseConnectionString)) {
          String insertTokens =
              "INSERT INTO demo (access_token, refresh_token) VALUES (?, ?)";
          PreparedStatement pstmt = conn.prepareStatement(insertTokens);
          pstmt.setString(1, accessToken);
          pstmt.setString(2, refreshToken);
          pstmt.executeUpdate();
        } catch (SQLException e) {
          System.err.println("Error storing tokens in database: " +
                             e.getMessage());
          throw e;
        }

        res.redirect("/");
        return "";
      } catch (Exception e) {
        res.status(500);
        return "Error exchanging code for tokens: " + e.getMessage();
      }
    });

    // Step 4: Use the access token to make an API call
    get("/me", (req, res) -> {
      String accessToken = null;
      try (var conn = DriverManager.getConnection(databaseConnectionString)) {
        try (var stmt = conn.createStatement()) {
          var rs = stmt.executeQuery("SELECT access_token FROM demo");
          if (rs.next()) {
            accessToken = rs.getString("access_token");
          } else {
            return "No access token found in database";
          }
        }
      } catch (SQLException e) {
        System.err.println("Error reading access token: " + e.getMessage());
        return "Error reading access token from database";
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
        System.out.println(response.body());
        return "API call failed with status code: " + response.statusCode();
      }

      res.type("application/json");
      return response.body();
    });

    // Step 5: Refresh the access token
    get("/auth/samsara/refresh", (req, res) -> {
      String refreshToken = null;
      try (var conn = DriverManager.getConnection(databaseConnectionString)) {
        try (var stmt = conn.createStatement()) {
          var rs = stmt.executeQuery("SELECT refresh_token FROM demo");
          if (rs.next()) {
            refreshToken = rs.getString("refresh_token");
          } else {
            return "No refresh token found in database";
          }
        }
      } catch (SQLException e) {
        System.err.println("Error reading refresh token: " + e.getMessage());
        return "Error reading refresh token from database";
      }

      // Create auth header with client credentials
      String auth = dotenv.get("SAMSARA_CLIENT_ID") + ":" +
                    dotenv.get("SAMSARA_CLIENT_SECRET");
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

      HttpResponse<String> response =
          client.send(request, HttpResponse.BodyHandlers.ofString());

      if (response.statusCode() != 200) {
        return "Token refresh failed with status code: " +
            response.statusCode();
      }

      // Parse response JSON
      JsonObject tokenData =
          JsonParser.parseString(response.body()).getAsJsonObject();

      if (!tokenData.has("access_token")) {
        String error = tokenData.has("error")
                           ? tokenData.get("error").getAsString()
                           : "Unknown error";
        String description =
            tokenData.has("error_description")
                ? tokenData.get("error_description").getAsString()
                : "No error description provided";
        return String.format("Failed to refresh token: %s - %s", error,
                             description);
      }

      String newAccessToken = tokenData.get("access_token").getAsString();
      String newRefreshToken = tokenData.get("refresh_token").getAsString();

      // Update tokens in database
      try (var conn = DriverManager.getConnection(databaseConnectionString)) {
        String sql = "UPDATE demo SET access_token = ?, refresh_token = ? "
                     + "WHERE refresh_token = ?";
        try (var stmt = conn.prepareStatement(sql)) {
          stmt.setString(1, newAccessToken);
          stmt.setString(2, newRefreshToken);
          stmt.setString(3, refreshToken);
          stmt.executeUpdate();
        }
      }

      res.redirect("/");
      return null;
    });

    // Revoke the access token
    get("/auth/samsara/revoke", (req, res) -> {
      // Get refresh token from database
      String refreshToken = null;
      try (var conn = DriverManager.getConnection(databaseConnectionString)) {
        try (var stmt = conn.createStatement()) {
          var rs = stmt.executeQuery("SELECT refresh_token FROM demo");
          if (rs.next()) {
            refreshToken = rs.getString("refresh_token");
          }
        }
      }

      if (refreshToken == null) {
        return "Refresh token not found";
      }

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
        // If the revoke request was successful, delete tokens from database
        try (var conn = DriverManager.getConnection(databaseConnectionString)) {
          try (var stmt = conn.createStatement()) {
            stmt.execute("DELETE FROM demo");
          }
        }

        res.redirect("/");
        return null;
      } else {
        return "Failed to revoke access token and refresh token";
      }
    });
  }
}
