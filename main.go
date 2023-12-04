package main

import (
	_ "encoding/json"
	_ "github.com/dgrijalva/jwt-go"
	"learnity-backend/auth"
	"net/http"
	_ "strconv"

	"learnity-backend/server"
)

func main() {
	// Gestion des routes
	server.Init()
	http.HandleFunc("/login", auth.LoginHandler)
	http.HandleFunc("/loginByJwt", auth.LoginByJwtHandler)
	http.HandleFunc("/register", auth.RegisterHandler)
	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		return
	}
}
