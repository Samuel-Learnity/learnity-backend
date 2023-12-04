package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/redis/go-redis/v9"
	_env "learnity-backend/.env"
	"learnity-backend/server"
	"net/http"
	"time"
)

func LoginByJwtHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Méthode non autorisée", http.StatusMethodNotAllowed)
		return
	}

	decoder := json.NewDecoder(r.Body)
	var requestData struct {
		Token string `json:"token"`
	}

	err := decoder.Decode(&requestData)
	if err != nil {
		http.Error(w, "Erreur lors de la lecture du corps de la demande", http.StatusBadRequest)
		return
	}

	// Vérifier le token JWT
	token, err := jwt.Parse(requestData.Token, func(token *jwt.Token) (interface{}, error) {
		return _env.JwtSecret, nil
	})

	if err != nil {
		http.Error(w, "Erreur lors de la validation du token JWT", http.StatusUnauthorized)
		return
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		// Vérifier la date d'expiration du token
		if exp, ok := claims["exp"].(float64); ok {
			expirationTime := time.Unix(int64(exp), 0)
			if time.Now().After(expirationTime) {
				http.Error(w, "Token JWT expiré", http.StatusUnauthorized)
				return
			}
		} else {
			http.Error(w, "Clé 'exp' non trouvée dans les revendications du token", http.StatusInternalServerError)
			return
		}

		// Récupérer l'identifiant de l'utilisateur (sub)
		sub, ok := claims["sub"].(string)
		if !ok {
			http.Error(w, "Clé 'sub' non trouvée dans les revendications du token", http.StatusInternalServerError)
			return
		}

		// Récupérer l'utilisateur depuis Redis
		userKey := fmt.Sprintf("user:%s", sub)
		userJSON, err := server.Client.Get(context.Background(), userKey).Result()
		if err == redis.Nil {
			http.Error(w, "Utilisateur non trouvé", http.StatusNotFound)
			return
		} else if err != nil {
			http.Error(w, "Erreur lors de la récupération de l'utilisateur depuis Redis", http.StatusInternalServerError)
			return
		}

		// Répondre avec l'utilisateur trouvé
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(userJSON))
	} else {
		http.Error(w, "Token JWT invalide", http.StatusUnauthorized)
	}
}
