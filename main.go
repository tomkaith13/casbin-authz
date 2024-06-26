package main

import (
	"net/http"

	"github.com/casbin/casbin/v2"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

func main() {
	r := chi.NewRouter()

	// Middleware for logging and recovery
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	// We can add policies per router using https://github.com/casbin/chi-authz

	// Dummy ACL Endpoint
	r.Get("/dummy", func(w http.ResponseWriter, r *http.Request) {

		e, err := casbin.NewEnforcer("./model.conf", "./policy.csv")
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		sub := "alice" // the user that wants to access a resource.
		obj := "claim" // the resource that is going to be accessed.
		act := "read"  // the operation that the user performs on the resource.

		if res, _ := e.Enforce(sub, obj, act); res {
			// permit alice to read claim
			w.Write([]byte("This is a dummy allowed endpoint!!!!"))
			w.WriteHeader(http.StatusOK)

		} else {
			// deny the request, show an error
			http.Error(w, "This is a dummy restricted endpoint!!!!", http.StatusForbidden)
			return
		}
	})

	// abac Endpoint
	r.Get("/abac", func(w http.ResponseWriter, r *http.Request) {
		type Subject struct {
			Name  string
			Group string
		}

		e, err := casbin.NewEnforcer("./abac.conf", "./abac_policy.csv")
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		subj := Subject{
			Name:  "alice",
			Group: "caregiver",
		}

		if res, _ := e.Enforce(subj, "/abac", "GET", "user1"); res {
			w.Write([]byte("This is a abac allowed endpoint!!!!"))
			w.WriteHeader(http.StatusOK)

		} else {
			// deny the request, show an error
			http.Error(w, "This is a abac restricted endpoint!!!!", http.StatusForbidden)
			return
		}
	})

	// abac-agent Endpoint
	r.Post("/abac-agent", func(w http.ResponseWriter, r *http.Request) {
		type Subject struct {
			Name  string
			Group string
		}

		e, err := casbin.NewEnforcer("./abac.conf", "./abac_policy.csv")
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		subj := Subject{
			Name:  "bob",
			Group: "agent",
		}

		if res, _ := e.Enforce(subj, "/abac-agent", "POST", "user3"); res {
			w.Write([]byte("This is a abac-agent allowed endpoint!!!!"))
			w.WriteHeader(http.StatusOK)

		} else {
			// deny the request, show an error
			http.Error(w, "This is a abac-agent restricted endpoint!!!!", http.StatusForbidden)
			return
		}
	})

	// abac-agent Endpoint
	r.Get("/abac-agent", func(w http.ResponseWriter, r *http.Request) {
		type Subject struct {
			Name  string
			Group string
		}

		e, err := casbin.NewEnforcer("./abac.conf", "./abac_policy.csv")
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		subj := Subject{
			Name:  "bob",
			Group: "agent",
		}

		if res, _ := e.Enforce(subj, "/abac-agent", "GET", "user2"); res {
			w.Write([]byte("This is a abac-agent allowed endpoint!!!!"))
			w.WriteHeader(http.StatusOK)

		} else {
			// deny the request, show an error
			http.Error(w, "This is a abac-agent restricted endpoint!!!!", http.StatusForbidden)
			return
		}
	})

	// Start Server
	http.ListenAndServe(":8080", r)
}
