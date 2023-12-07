package auth

import (
	"context"
	"encoding/json"
	"fmt"
	jwt "github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
	_env "learnity-backend/.env"
	"learnity-backend/models"
	"learnity-backend/server"
	"log"
	"net/http"
	"strconv"
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

	// Rechercher l'utilisateur par email parmi tous les utilisateurs
	var user models.User
	var userID int

	// Récupérer le nombre total d'utilisateurs
	totalUsersStr, err := server.Client.Get(context.Background(), "user:id").Result()
	if err != nil {
		http.Error(w, "Erreur lors de la récupération du nombre total d'utilisateurs", http.StatusInternalServerError)
		return
	}

	totalUsers, err := strconv.Atoi(totalUsersStr)
	if err != nil {
		http.Error(w, "Erreur lors de la conversion du nombre total d'utilisateurs en entier", http.StatusInternalServerError)
		return
	}
	// Parcourir tous les utilisateurs
	for i := 1; i <= totalUsers; i++ {
		userIDKey := fmt.Sprintf("users:%d", i)
		userJSON, err := server.Client.Get(context.Background(), userIDKey).Result()
		if err != nil {
			// Ignorer les erreurs et passer à l'utilisateur suivant
			continue
		}

		err = json.Unmarshal([]byte(userJSON), &user)
		if err != nil {
			http.Error(w, "Erreur lors de la désérialisation de l'utilisateur depuis JSON", http.StatusInternalServerError)
			return
		}

		// Vérifier si l'e-mail correspond
		if user.Email == credentials.Email {
			userID = i
			break
		}
	}

	// Si l'utilisateur n'est pas trouvé, renvoyer une erreur
	if userID == 0 {
		http.Error(w, "Utilisateur non trouvé", http.StatusNotFound)
		return
	}

	// Vérifier le mot de passe avec Bcrypt
	if err := bcrypt.CompareHashAndPassword([]byte(user.HashedPassword), []byte(credentials.Password)); err != nil {
		log.Print("Mot de passe incorrect 401")
		http.Error(w, "Mot de passe incorrect", http.StatusUnauthorized)
		return
	}

	// Créer un nouveau JWT
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["sub"] = userID                                     // Utiliser l'ID comme identifiant
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
	userJSON := string(userJSONBytes)

	err = server.Client.Set(context.Background(), fmt.Sprintf("users:%d", userID), userJSON, 0).Err()
	if err != nil {
		http.Error(w, "Erreur lors de la mise à jour de l'utilisateur dans Redis", http.StatusInternalServerError)
		return
	}

	// Répondre avec le token JWT
	w.Header().Set("Content-Type", "application/json")
	response := map[string]string{"token": tokenString}
	json.NewEncoder(w).Encode(response)
}
