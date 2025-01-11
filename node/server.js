const express = require("express");
const session = require("express-session");
const crypto = require("crypto");
const sqlite3 = require("sqlite3").verbose();
const db = new sqlite3.Database("demo.db");

const fetch = (...args) =>
  import("node-fetch").then(({ default: fetch }) => fetch(...args));

require("dotenv").config();

const app = express();

// Session middleware configuration
app.use(
  session({
    secret: crypto.randomBytes(32).toString("hex"),
    resave: false,
    saveUninitialized: true,
  })
);

// Get environment variables
const SAMSARA_CLIENT_ID = process.env.SAMSARA_CLIENT_ID;
const SAMSARA_CLIENT_SECRET = process.env.SAMSARA_CLIENT_SECRET;

app.get("/", async (req, res) => {
  let accessToken = "No access token stored locally.";
  const credentials = await getCredentials();

  if (!credentials) {
    accessToken = "No access token stored locally.";
  } else {
    accessToken = credentials.access_token;
  }

  res.send(`
      <html>
        <body>
          <p>Access Token: <pre>${accessToken}</pre></p>
          <a href="/auth/samsara">Connect to Samsara</a><br /><br />

          <a href="/me">Test API Call</a><br>
          <a href="/auth/samsara/refresh">Refresh Access Token</a><br>
          <a href="/auth/samsara/revoke">Revoke Access Token</a><br>
        </body>
      </html>
  `);
});

// Step 1: Redirect to Samsara's OAuth 2.0 authorization flow
app.get("/auth/samsara", (req, res) => {
  // Generate random state for CSRF protection
  const state = crypto.randomBytes(16).toString("base64url");

  // Store in the session state to verify in Step 2.
  req.session.oauth_state = state;

  const params = new URLSearchParams({
    client_id: SAMSARA_CLIENT_ID,
    response_type: "code",
    redirect_uri: "http://localhost:5000/auth/samsara/callback",
    state: state,
  });

  const redirectUrl = `https://api.samsara.com/oauth2/authorize?${params.toString()}`;

  res.redirect(redirectUrl);
});

// Step 2: Handle the callback from Samsara's OAuth 2.0 authorization flow
app.get("/auth/samsara/callback", async (req, res) => {
  // Get the authorization code and state from the query params.
  const { code, state } = req.query;

  // Verify state to prevent CSRF attacks
  if (!state || state !== req.session.oauth_state) {
    return res.status(400).send("Invalid state parameter");
  }

  // Clear state from session
  delete req.session.oauth_state;

  if (code) {
    try {
      // Create authorization header
      const auth = Buffer.from(
        `${SAMSARA_CLIENT_ID}:${SAMSARA_CLIENT_SECRET}`
      ).toString("base64");

      // Step 3: Exchange authorization code for access token
      const response = await fetch("https://api.samsara.com/oauth2/token", {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          Authorization: `Basic ${auth}`,
        },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          code: code,
        }),
      });

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const tokenData = await response.json();

      // Store tokens in database
      const stmt = db.prepare(
        "INSERT INTO demo (access_token, refresh_token) VALUES (?, ?)"
      );
      stmt.run(tokenData.access_token, tokenData.refresh_token);
      stmt.finalize();

      return res.redirect("/");
    } catch (error) {
      console.error("Error exchanging code for token:", error);
      return res
        .status(400)
        .send(`Error getting access token: ${error.message}`);
    }
  } else {
    // Handle error cases
    const error = req.query.error;
    const errorDescription = req.query.error_description;
    return res
      .status(400)
      .send(`Authorization failed: ${error} - ${errorDescription}`);
  }
});

// Step 4: Use the access token to make an API call
app.get("/me", async (req, res) => {
  const credentials = await getCredentials();
  if (!credentials) {
    return res.status(400).send("No access token stored locally.");
  }

  const accessToken = credentials.access_token;

  const response = await fetch("https://api.samsara.com/me", {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": "application/json",
    },
  });

  return res.json(await response.json());
});

// Step 5: Refresh the access token
app.get("/auth/samsara/refresh", async (req, res) => {
  const credentials = await getCredentials();
  if (!credentials) {
    return res.status(400).send("No access token stored locally.");
  }

  const refreshToken = credentials.refresh_token;

  const auth = Buffer.from(
    `${SAMSARA_CLIENT_ID}:${SAMSARA_CLIENT_SECRET}`
  ).toString("base64");

  const response = await fetch("https://api.samsara.com/oauth2/token", {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Authorization: `Basic ${auth}`,
    },
    body: new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: refreshToken,
    }),
  });

  const tokenData = await response.json();
  const newAccessToken = tokenData.access_token;
  const newRefreshToken = tokenData.refresh_token;

  const stmt = db.prepare(
    "UPDATE demo SET access_token = ?, refresh_token = ? WHERE refresh_token = ?"
  );
  stmt.run(newAccessToken, newRefreshToken, refreshToken);
  stmt.finalize();

  return res.redirect("/");
});

// Revoke the access token
app.get("/auth/samsara/revoke", async (req, res) => {
  const credentials = await getCredentials();
  if (!credentials) {
    return res.status(400).send("No access token stored locally.");
  }

  const refreshToken = credentials.refresh_token;

  const auth = Buffer.from(
    `${SAMSARA_CLIENT_ID}:${SAMSARA_CLIENT_SECRET}`
  ).toString("base64");

  const response = await fetch("https://api.samsara.com/oauth2/revoke", {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Authorization: `Basic ${auth}`,
    },
    body: new URLSearchParams({
      token: refreshToken,
    }),
  });

  if (response.ok) {
    const stmt = db.prepare("DELETE FROM demo");
    stmt.run();
    stmt.finalize();
  }

  return res.redirect("/");
});

// Initialize database schema
db.serialize(() => {
  // Drop existing table if it exists
  db.run("DROP TABLE IF EXISTS demo");

  // Create new table
  db.run(`
    CREATE TABLE demo (
      access_token TEXT,
      refresh_token TEXT
    )
  `);
});

const getCredentials = async () => {
  return new Promise((resolve, reject) => {
    db.get("SELECT access_token, refresh_token FROM demo", (err, row) => {
      if (err) {
        return reject(err);
      }
      resolve(row);
    });
  });
};

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT} at http://localhost:${PORT}`);
});
