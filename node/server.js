const express = require("express");
const session = require("express-session");
const crypto = require("crypto");

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
const SAMSARA_TOKEN_URL = "https://api.samsara.com/oauth2/token";

app.get("/", (req, res) => {
  // Store state in session
  res.send("Hello World <a href='/authorize'>Authorize</a>");
});

app.get("/authorize", (req, res) => {
  // Generate random state for CSRF protection
  const state = crypto.randomBytes(16).toString("base64url");
  console.log({ state });
  req.session.oauth_state = state;

  console.log(req.session.oauth_state);

  const redirectUrl = `https://api.samsara.com/oauth2/authorize?client_id=${SAMSARA_CLIENT_ID}&response_type=code&redirect_uri=${encodeURIComponent(
    "http://localhost:5000/callback"
  )}&state=${state}`;

  console.log({ redirectUrl });

  res.redirect(redirectUrl);
});

app.get("/callback", async (req, res) => {
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

      // Exchange authorization code for access token
      const response = await fetch(SAMSARA_TOKEN_URL, {
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
      console.log(tokenData);
      const accessToken = tokenData.access_token;

      // TODO: Store the access token securely
      // For now, we'll just log it (don't do this in production!)
      console.log(`Access Token: ${accessToken}`);

      return res.send("Successfully connected to Samsara!");
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

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
