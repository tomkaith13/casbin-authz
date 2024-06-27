package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/casbin/casbin/v2"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

type Subject struct {
	Name  string
	Group string
}

func main() {
	r := chi.NewRouter()

	// Middleware for logging and recovery
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	// We can add policies per router using https://github.com/casbin/chi-authz

	cachedE, err := casbin.NewCachedEnforcer("./abac_custom.conf", "./abac_custom_policy.csv")
	if err != nil {
		fmt.Println("error initializing")
		return
	}

	cachedE.AddFunction("my_func", KeyMatchFunc)
	d := 600 * time.Second
	cachedE.SetExpireTime(d)
	cachedE.EnableCache(true)

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

	// abac-agent Endpoint
	r.Get("/abac-agent-custom", func(w http.ResponseWriter, r *http.Request) {

		subj := Subject{
			Name:  "bobby",
			Group: "agent-custom",
		}

		res, err := cachedE.Enforce(subj, "/abac-agent-custom", "GET", "user2")
		if err != nil {
			// deny the request, show an error
			http.Error(w, "This is a abac-agent-custom restricted endpoint!!!!"+err.Error(), http.StatusForbidden)
			return
		}

		if res {
			w.Write([]byte("This is a abac-agent-custom allowed endpoint!!!!"))
			w.WriteHeader(http.StatusOK)

		} else {
			http.Error(w, "This is a abac-agent-custom restricted endpoint!!!! enforce failed", http.StatusForbidden)
		}
	})

	// Start Server
	http.ListenAndServe(":8080", r)
}

func CustomMatch(lval string, rval Subject) bool {
	//  Imagine a long network call to authz from another endpoint
	time.Sleep(2 * time.Second)

	fmt.Println("custom auth checked!!")
	return lval == rval.Name
}

func KeyMatchFunc(args ...interface{}) (interface{}, error) {
	lval := args[0].(string)
	rval := args[1].(Subject)
	fmt.Println("policy val:", lval)
	fmt.Println("req val:", rval)

	return (bool)(CustomMatch(lval, rval)), nil
}
