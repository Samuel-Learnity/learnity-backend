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
	"time"
)

func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Méthode non autorisée", http.StatusMethodNotAllowed)
		return
	}

	log.Print("Register")

	decoder := json.NewDecoder(r.Body)
	var newUser models.User

	err := decoder.Decode(&newUser)
	if err != nil {
		http.Error(w, "Erreur lors de la lecture du corps de la demande", http.StatusBadRequest)
		return
	}

	// Vérifier si l'utilisateur existe déjà
	exists, err := server.Client.SIsMember(context.Background(), "users", newUser.Email).Result()
	if err != nil {
		http.Error(w, "Erreur lors de la vérification de l'existence de l'utilisateur", http.StatusInternalServerError)
		return
	}

	if exists {
		http.Error(w, "E-mail déjà pris", http.StatusConflict)
		return
	}

	// Générer un nouvel ID utilisateur
	userID, err := server.Client.Incr(context.Background(), "user:id").Result()
	if err != nil {
		http.Error(w, "Erreur lors de la génération de l'ID utilisateur", http.StatusInternalServerError)
		return
	}

	// Utiliser l'ID généré comme clé pour l'utilisateur dans Redis
	newUser.ID = int(userID)
	key := fmt.Sprintf("users:%d", userID)

	// Ajouter l'ID utilisateur à l'ensemble "users" dans Redis
	err = server.Client.SAdd(context.Background(), "users", key).Err()
	if err != nil {
		http.Error(w, "Erreur lors de l'ajout de l'ID utilisateur à l'ensemble dans Redis", http.StatusInternalServerError)
		return
	}

	// Chiffrer le mot de passe avec bcrypt
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newUser.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Erreur lors du chiffrement du mot de passe", http.StatusInternalServerError)
		return
	}

	// Stocker le mot de passe chiffré dans le modèle d'utilisateur
	newUser.Password = "" // Effacer le mot de passe non chiffré
	newUser.HashedPassword = string(hashedPassword)

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
	newUser.Token = tokenString
	newUser.TokenExpireAt = claims["exp"].(int64)

	// Convertir l'utilisateur en JSON et le stocker dans Redis
	userJSONBytes, err := json.Marshal(newUser)
	if err != nil {
		http.Error(w, "Erreur lors de la sérialisation de l'utilisateur en JSON", http.StatusInternalServerError)
		return
	}

	// Convertir le tableau d'octets en chaîne de caractères
	userJSON := string(userJSONBytes)

	// Utiliser l'ID comme clé pour stocker l'utilisateur dans Redis
	err = server.Client.Set(context.Background(), key, userJSON, 0).Err()
	if err != nil {
		http.Error(w, "Erreur lors de la sauvegarde de l'utilisateur dans Redis", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	// Répondre avec le token JWT
	w.Header().Set("Content-Type", "application/json")
	response := map[string]string{"token": tokenString}
	json.NewEncoder(w).Encode(response)
}
