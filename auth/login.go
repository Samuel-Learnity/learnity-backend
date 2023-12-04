package auth

import (
	"context"
	"encoding/json"
	"fmt"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/redis/go-redis/v9"
	_env "learnity-backend/.env"
	"learnity-backend/models"
	"learnity-backend/server"
	"log"
	"net/http"
	"time"
)

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Méthode non autorisée", http.StatusMethodNotAllowed)
		return
	}

	decoder := json.NewDecoder(r.Body)
	var credentials struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	err := decoder.Decode(&credentials)
	if err != nil {
		http.Error(w, "Erreur lors de la lecture du corps de la demande", http.StatusBadRequest)
		return
	}

	log.Print("LOGIN")

	// Rechercher l'utilisateur par email
	userKey := fmt.Sprintf("users:%s", credentials.Email)
	userJSON, err := server.Client.Get(context.Background(), userKey).Result()
	if err == redis.Nil {
		http.Error(w, "Utilisateur non trouvé", http.StatusNotFound)
		return
	} else if err != nil {
		http.Error(w, "Erreur lors de la récupération de l'utilisateur depuis Redis", http.StatusInternalServerError)
		return
	}

	var user models.User
	err = json.Unmarshal([]byte(userJSON), &user)
	if err != nil {
		http.Error(w, "Erreur lors de la désérialisation de l'utilisateur depuis JSON", http.StatusInternalServerError)
		return
	}

	// Vérifier le mot de passe
	if user.Password != credentials.Password {
		http.Error(w, "Mot de passe incorrect", http.StatusUnauthorized)
		return
	}

	// Créer un nouveau JWT
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["sub"] = user.Email                                 // Utiliser l'e-mail comme identifiant
	claims["exp"] = time.Now().Add(time.Hour * 24 * 30).Unix() // Expiration en 30 jours

	// Signer le JWT avec la clé secrète
	tokenString, err := token.SignedString(_env.JwtSecret)
	if err != nil {
		http.Error(w, "Erreur lors de la création du token JWT", http.StatusInternalServerError)
		return
	}

	// Mettre à jour le token dans l'utilisateur
	user.Token = tokenString
	user.TokenExpireAt = claims["exp"].(int64)

	// Mettre à jour l'utilisateur dans Redis
	userJSONBytes, err := json.Marshal(user)
	if err != nil {
		http.Error(w, "Erreur lors de la sérialisation de l'utilisateur en JSON", http.StatusInternalServerError)
		return
	}

	// Convertir le tableau d'octets en chaîne de caractères
	userJSON = string(userJSONBytes)

	err = server.Client.Set(context.Background(), userKey, userJSON, 0).Err()
	if err != nil {
		http.Error(w, "Erreur lors de la mise à jour de l'utilisateur dans Redis", http.StatusInternalServerError)
		return
	}

	// Répondre avec le token JWT
	w.Header().Set("Content-Type", "application/json")
	response := map[string]string{"token": tokenString}
	json.NewEncoder(w).Encode(response)
}
