package com.samsara.dev;

import static spark.Spark.*;

public class Server {
    public static void main(String[] args) {
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
    }
}
