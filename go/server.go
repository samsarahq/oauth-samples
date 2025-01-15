package main

import (
	"encoding/base64"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/gorilla/sessions"

	"github.com/joho/godotenv"
)

var store = sessions.NewCookieStore([]byte("your-secret-key"))

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	// Register the map type for session storage
	gob.Register(map[string]interface{}{})

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
	session, _ := store.Get(r, "session")
	credentials := session.Values["credentials"]
	fmt.Println(session.Values)

	var accessToken string
	if credentials != nil {
		accessToken = credentials.(map[string]interface{})["access_token"].(string)
	} else {
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
	data.Set("redirect_uri", "http://localhost:5000/auth/samsara/callback")

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

	// Store tokens in session
	session.Values["credentials"] = map[string]interface{}{
		"access_token":  result.AccessToken,
		"refresh_token": result.RefreshToken,
		"expires_at":    time.Now().Unix(), // + int64(result.ExpiresIn),

	}
	if err := session.Save(r, w); err != nil {
		log.Printf("Error saving session: %v", err)
	}

	http.Redirect(w, r, "/", http.StatusFound)
}

// Step 4: Use the access token to make an API call
func handleMe(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session")
	credentials := session.Values["credentials"]

	if credentials == nil {
		http.Error(w, "No credentials found", http.StatusUnauthorized)
		return
	}

	// If the tokens are expired, refresh them
	if credentials.(map[string]interface{})["expires_at"].(int64) < time.Now().Unix() {
		handleRefresh(w, r)
	}

	accessToken := credentials.(map[string]interface{})["access_token"].(string)

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
	session, _ := store.Get(r, "session")
	credentials := session.Values["credentials"]

	if credentials == nil {
		http.Error(w, "No credentials found", http.StatusUnauthorized)
		return
	}

	refreshToken := credentials.(map[string]interface{})["refresh_token"].(string)

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
		ExpiresIn    int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenData); err != nil {
		http.Error(w, "Error parsing response", http.StatusInternalServerError)
		return
	}

	// Update tokens in session
	session.Values["credentials"] = map[string]interface{}{
		"access_token":  tokenData.AccessToken,
		"refresh_token": tokenData.RefreshToken,
		"expires_at":    time.Now().Unix() + int64(tokenData.ExpiresIn),
	}
	if err := session.Save(r, w); err != nil {
		log.Printf("Error saving session: %v", err)
	}

	http.Redirect(w, r, "/", http.StatusFound)
}

// Step 6: Revoke the access token
func handleRevoke(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session")
	credentials := session.Values["credentials"]

	if credentials == nil {
		http.Error(w, "No credentials found", http.StatusUnauthorized)
		return
	}

	refreshToken := credentials.(map[string]interface{})["refresh_token"].(string)

	// Create auth header
	auth := os.Getenv("SAMSARA_CLIENT_ID") + ":" + os.Getenv("SAMSARA_CLIENT_SECRET")
	basicAuth := base64.StdEncoding.EncodeToString([]byte(auth))

	// Create request with refresh token in body
	client := &http.Client{}
	data := url.Values{}
	data.Set("token", refreshToken)
	req, err := http.NewRequest("POST", "https://api.samsara.com/oauth2/revoke", strings.NewReader(data.Encode()))
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
		delete(session.Values, "credentials")
		session.Save(r, w)
	}

	defer resp.Body.Close()

	http.Redirect(w, r, "/", http.StatusFound)
}
