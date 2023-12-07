package main

import (
	_ "encoding/json"
	_ "github.com/dgrijalva/jwt-go"
	"learnity-backend/src/auth"
	"learnity-backend/src/user"
	"net/http"
	_ "strconv"

	"learnity-backend/server"
)

func main() {
	// Gestion des routes
	server.Init()
	http.HandleFunc("/login", auth.LoginHandler)
	http.HandleFunc("/register", auth.RegisterHandler)
	http.HandleFunc("/user", user.UserHandler)
	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		return
	}
}
