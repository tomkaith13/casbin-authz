package main

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

func main() {
	r := chi.NewRouter()

	// Middleware for logging and recovery
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	// Dummy Endpoint
	r.Get("/dummy", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("This is a dummy endpoint!!!!"))
	})

	// Start Server
	http.ListenAndServe(":8080", r)
}
