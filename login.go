package main

import (
	"context"
	"embed"
	"html/template"
	"log/slog"
	"net/http"
	"strings"

	"github.com/google/uuid"
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
				slog.Error("html error: %v", err)
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
			w.WriteHeader(http.StatusBadRequest)
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

	var existingUser *user
	for _, v := range s.users {
		if v.username == username {
			existingUser = v
		}
	}

	if existingUser == nil {
		user := user{
			id:       uuid.NewString(),
			name:     strings.ToUpper(username[:1]) + username[1:],
			username: username,
		}
		s.users[user.id] = &user
		existingUser = &user
	}

	s.authRequests[authRequestID].subject = existingUser.id
	s.authRequests[authRequestID].done = true

	callbackURL := buildCallbackURL(r.Context(), authRequestID)
	http.Redirect(w, r, callbackURL, http.StatusTemporaryRedirect)
}
