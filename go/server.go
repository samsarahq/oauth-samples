package main

import (
	"fmt"
	"log"	
	"net/http"
	"os"
	"strings"
	"encoding/json"
	"encoding/base64"
	"net/url"

	"github.com/joho/godotenv"
)

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	fmt.Println("Hello, World!")

	http.Handle("/", http.FileServer(http.Dir("./static")))
	http.HandleFunc("/authorize", handleAuthorize)
	http.HandleFunc("/callback", handleCallback)
	
	http.ListenAndServe(":5000", nil)
}

func handleAuthorize(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Hello, World!")

	// Generate random state parameter to prevent CSRF
	state := "testingandhastobelong"

	// Build authorization URL
	authURL := "https://api.samsara.com/oauth2/authorize"
	params := map[string]string{
		"client_id":     os.Getenv("SAMSARA_CLIENT_ID"),
		"response_type": "code",
		"state":        state,
	}

	// Add optional redirect_uri if specified
	if redirectURI := os.Getenv("REDIRECT_URI"); redirectURI != "" {
		params["redirect_uri"] = redirectURI
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

func handleCallback(w http.ResponseWriter, r *http.Request) {
	// Get authorization code from query params
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	fmt.Printf("State: %s\n", state)

	if code == "" {
		http.Error(w, "Missing authorization code", http.StatusBadRequest)
		return
	}

	// Create HTTP client
	client := &http.Client{}

	// Prepare token request
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
	fmt.Printf("Access Token: %s\n", result.AccessToken)
	fmt.Printf("Refresh Token: %s\n", result.RefreshToken)

	w.Write([]byte("Authorization successful!"))
}
