package oidc

import (
	"context"
	"embed"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
)

var (
	//go:embed templates
	fs        embed.FS
	templates = template.Must(template.ParseFS(fs, "templates/*.html"))
)

func loginForm(s *inmemStorage, buildCallbackURL func(context.Context, string) string) func(w http.ResponseWriter, r *http.Request) {

	return func(w http.ResponseWriter, r *http.Request) {
		authRequestID := r.FormValue("authRequestID")
		username := r.FormValue("username")

		// Validate authRequestID exists
		if authRequestID == "" {
			slog.Error("missing authRequestID parameter")
			http.Error(w, "Missing authentication request ID", http.StatusBadRequest)
			return
		}

		// Check if auth request exists
		s.lock.Lock()
		_, exists := s.authRequests[authRequestID]
		s.lock.Unlock()

		if !exists {
			slog.Error("auth request not found in login form", "authRequestID", authRequestID)
			http.Error(w, "Invalid authentication request", http.StatusBadRequest)
			return
		}

		// if a username is set, skip the form and go straight to login
		// this is used by automated tests to login
		if len(username) > 0 {
			completeLogin(username, authRequestID, w, r, s, buildCallbackURL)
		} else {
			data := &struct {
				ID string
			}{ID: authRequestID}
			err := templates.ExecuteTemplate(w, "login", data)
			if err != nil {
				_, _ = w.Write([]byte(fmt.Sprintf("html error: %v", err)))
				w.WriteHeader(http.StatusInternalServerError)
			}
		}
	}
}

func loginPost(s *inmemStorage, buildCallbackURL func(context.Context, string) string) func(w http.ResponseWriter, r *http.Request) {

	return func(w http.ResponseWriter, r *http.Request) {
		username := r.FormValue("username")
		authRequestID := r.FormValue("id")

		if len(username) == 0 {
			slog.Error("username too short")
			http.Error(w, "Username is required", http.StatusBadRequest)
			return
		}

		if authRequestID == "" {
			slog.Error("missing authRequestID parameter in POST")
			http.Error(w, "Missing authentication request ID", http.StatusBadRequest)
			return
		}

		completeLogin(username, authRequestID, w, r, s, buildCallbackURL)
	}
}

func completeLogin(
	username string,
	authRequestID string,
	w http.ResponseWriter,
	r *http.Request,
	s *inmemStorage,
	buildCallbackURL func(context.Context, string) string,
) {
	s.lock.Lock()
	defer s.lock.Unlock()

	// Check if auth request exists
	authRequest, exists := s.authRequests[authRequestID]
	if !exists {
		slog.Error("auth request not found", "authRequestID", authRequestID)
		http.Error(w, "Invalid authentication request", http.StatusBadRequest)
		return
	}

	var existingUser *user
	for _, v := range s.users {
		if v.username == username {
			existingUser = v
		}
	}

	if existingUser == nil {
		// Create user from configuration
		user := createUserFromConfig(username, s.appConfig.UserData.DefaultUser)
		s.users[user.id] = user
		existingUser = user
	}

	authRequest.subject = existingUser.id
	authRequest.done = true

	callbackURL := buildCallbackURL(r.Context(), authRequestID)
	http.Redirect(w, r, callbackURL, http.StatusTemporaryRedirect)
}
