package main

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/gorilla/sessions"

	_ "github.com/mattn/go-sqlite3"

	"github.com/joho/godotenv"
)

var store = sessions.NewCookieStore([]byte("your-secret-key"))

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	initDB()

	http.HandleFunc("/", handleHome)
	http.HandleFunc("/auth/samsara", handleAuthorize)
	http.HandleFunc("/auth/samsara/callback", handleCallback)
	http.HandleFunc("/me", handleMe)
	http.HandleFunc("/auth/samsara/refresh", handleRefresh)
	http.HandleFunc("/auth/samsara/revoke", handleRevoke)

	http.ListenAndServe(":5000", nil)

	fmt.Println("Server running on port 5000 at http://localhost:5000")
}

func handleHome(w http.ResponseWriter, r *http.Request) {
	// Get access token from database
	db, err := sql.Open("sqlite3", "demo.db")
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer db.Close()

	var accessToken string
	err = db.QueryRow("SELECT access_token FROM demo").Scan(&accessToken)
	if err != nil {
		accessToken = "No access token stored locally."
	}

	html := fmt.Sprintf(`
		<html>
			<body>
				<p>Access Token: <pre>%s</pre></p>
				<a href="/auth/samsara">Connect to Samsara</a><br /><br />

				<a href="/me">Test API Call</a><br>
				<a href="/auth/samsara/refresh">Refresh Access Token</a><br>
				<a href="/auth/samsara/revoke">Revoke Access Token</a><br>
			</body>
		</html>
	`, accessToken)

	fmt.Fprint(w, html)
}

// Step 1: Redirect user to Samsara authorization page
func handleAuthorize(w http.ResponseWriter, r *http.Request) {
	// Generate random state parameter to prevent CSRF
	state := fmt.Sprintf("%x", rand.Int63())

	// Store state in session
	session, _ := store.Get(r, "session")
	session.Values["state"] = state
	session.Save(r, w)

	// Build authorization URL
	authURL := "https://api.samsara.com/oauth2/authorize"
	params := map[string]string{
		"client_id":     os.Getenv("SAMSARA_CLIENT_ID"),
		"response_type": "code",
		"state":         state,
		"redirect_uri":  "http://localhost:5000/auth/samsara/callback",
	}

	// Build query string
	var queryParams []string
	for key, value := range params {
		queryParams = append(queryParams, fmt.Sprintf("%s=%s", key, value))
	}
	authURL = authURL + "?" + strings.Join(queryParams, "&")

	// Redirect user to Samsara authorization page
	http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)
}

// Step 2: Handle callback from Samsara
func handleCallback(w http.ResponseWriter, r *http.Request) {
	// Get authorization code from query params
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	// Get state from session
	session, _ := store.Get(r, "session")
	expectedState := session.Values["state"]

	// Verify state parameter to prevent CSRF
	if state != expectedState {
		http.Error(w, "Invalid state parameter", http.StatusBadRequest)
		return
	}

	// Clear state from session
	delete(session.Values, "state")
	session.Save(r, w)

	fmt.Printf("State: %s\n", state)

	if code == "" {
		http.Error(w, "Missing authorization code", http.StatusBadRequest)
		return
	}

	// Create HTTP client
	client := &http.Client{}

	// Step 3: Exchange authorization code for access and refresh tokens
	tokenURL := "https://api.samsara.com/oauth2/token"
	data := url.Values{}
	data.Set("code", code)
	data.Set("grant_type", "authorization_code")

	req, err := http.NewRequest("POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		http.Error(w, "Error creating token request", http.StatusInternalServerError)
		return
	}

	// Add headers
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	// Add basic auth header
	auth := os.Getenv("SAMSARA_CLIENT_ID") + ":" + os.Getenv("SAMSARA_CLIENT_SECRET")
	basicAuth := base64.StdEncoding.EncodeToString([]byte(auth))
	req.Header.Add("Authorization", "Basic "+basicAuth)

	// Make request
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, "Error exchanging code for token", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	// Parse response
	var result struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
		TokenType    string `json:"token_type"`
		Scope        string `json:"scope"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		http.Error(w, "Error parsing token response", http.StatusInternalServerError)
		return
	}

	// Print tokens
	// Store tokens in database
	db, err := sql.Open("sqlite3", "./demo.db")
	if err != nil {
		http.Error(w, "Error opening database", http.StatusInternalServerError)
		return
	}
	defer db.Close()

	_, err = db.Exec("INSERT INTO demo (access_token, refresh_token) VALUES (?, ?)",
		result.AccessToken, result.RefreshToken)
	if err != nil {
		http.Error(w, "Error storing tokens in database", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/", http.StatusFound)
}

// Step 4: Use the access token to make an API call
func handleMe(w http.ResponseWriter, r *http.Request) {
	// Get access token from database
	db, err := sql.Open("sqlite3", "./demo.db")
	if err != nil {
		http.Error(w, "Error opening database", http.StatusInternalServerError)
		return
	}
	defer db.Close()

	var accessToken string
	err = db.QueryRow("SELECT access_token FROM demo").Scan(&accessToken)
	if err != nil {
		http.Error(w, "Error retrieving access token", http.StatusInternalServerError)
		return
	}

	// Create request
	client := &http.Client{}
	req, err := http.NewRequest("GET", "https://api.samsara.com/me", nil)
	if err != nil {
		http.Error(w, "Error creating request", http.StatusInternalServerError)
		return
	}

	// Add headers
	req.Header.Add("Authorization", "Bearer "+accessToken)
	req.Header.Add("Content-Type", "application/json")

	// Make request
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, "Error making request", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	// Copy response body to response writer
	w.Header().Set("Content-Type", "application/json")
	io.Copy(w, resp.Body)
}

// Step 5: Refresh the access token
func handleRefresh(w http.ResponseWriter, r *http.Request) {
	// Get refresh token from database
	db, err := sql.Open("sqlite3", "./demo.db")
	if err != nil {
		http.Error(w, "Error opening database", http.StatusInternalServerError)
		return
	}
	defer db.Close()

	var refreshToken string
	err = db.QueryRow("SELECT refresh_token FROM demo").Scan(&refreshToken)
	if err != nil {
		http.Error(w, "Error retrieving refresh token", http.StatusInternalServerError)
		return
	}

	// Create auth header
	auth := os.Getenv("SAMSARA_CLIENT_ID") + ":" + os.Getenv("SAMSARA_CLIENT_SECRET")
	basicAuth := base64.StdEncoding.EncodeToString([]byte(auth))

	// Create form data
	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", refreshToken)

	// Create request
	client := &http.Client{}
	req, err := http.NewRequest("POST", "https://api.samsara.com/oauth2/token", strings.NewReader(data.Encode()))
	if err != nil {
		http.Error(w, "Error creating request", http.StatusInternalServerError)
		return
	}

	// Add headers
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Authorization", "Basic "+basicAuth)

	// Make request
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, "Error making request", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	// Parse response
	var tokenData struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenData); err != nil {
		http.Error(w, "Error parsing response", http.StatusInternalServerError)
		return
	}

	// Update tokens in database
	_, err = db.Exec("UPDATE demo SET access_token = ?, refresh_token = ? WHERE refresh_token = ?",
		tokenData.AccessToken, tokenData.RefreshToken, refreshToken)
	if err != nil {
		http.Error(w, "Error updating tokens", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/", http.StatusFound)
}

// Step 6: Revoke the access token
func handleRevoke(w http.ResponseWriter, r *http.Request) {
	// Get refresh token from database
	db, err := sql.Open("sqlite3", "./demo.db")
	if err != nil {
		http.Error(w, "Error opening database", http.StatusInternalServerError)
		return
	}
	defer db.Close()

	// Get refresh token from database
	var refreshToken string
	err = db.QueryRow("SELECT refresh_token FROM demo").Scan(&refreshToken)
	if err != nil {
		http.Error(w, "Error retrieving refresh token", http.StatusInternalServerError)
		return
	}

	// Create auth header
	auth := os.Getenv("SAMSARA_CLIENT_ID") + ":" + os.Getenv("SAMSARA_CLIENT_SECRET")
	basicAuth := base64.StdEncoding.EncodeToString([]byte(auth))

	// Create request
	client := &http.Client{}
	req, err := http.NewRequest("POST", "https://api.samsara.com/oauth2/revoke", nil)
	if err != nil {
		http.Error(w, "Error creating request", http.StatusInternalServerError)
		return
	}

	// Add headers
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Authorization", "Basic "+basicAuth)

	// Make request
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, "Error making request", http.StatusInternalServerError)
		return
	}

	if resp.StatusCode == http.StatusOK {
		_, err = db.Exec("DELETE FROM demo")
		if err != nil {
			http.Error(w, "Error deleting tokens from database", http.StatusInternalServerError)
			return
		}
	}

	defer resp.Body.Close()

	http.Redirect(w, r, "/", http.StatusFound)
}

// Initialize database schema
func initDB() {
	db, err := sql.Open("sqlite3", "./demo.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// Drop existing table if it exists
	_, err = db.Exec("DROP TABLE IF EXISTS demo")
	if err != nil {
		log.Fatal(err)
	}

	// Create new table
	_, err = db.Exec(`
		CREATE TABLE demo (
			access_token TEXT,
			refresh_token TEXT
		)
	`)
	if err != nil {
		log.Fatal(err)
	}
}
