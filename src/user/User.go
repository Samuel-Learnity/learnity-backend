package user

import (
	"context"
	"encoding/json"
	"fmt"
	jwt "github.com/dgrijalva/jwt-go"
	_env "learnity-backend/.env"
	"learnity-backend/models"
	"learnity-backend/server"
	"log"
	"net/http"
)

func UserHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Méthode non autorisée", http.StatusMethodNotAllowed)
		return
	}

	log.Print("USER HANDLER")

	var tokenPayload struct {
		Token string `json:"token"`
	}

	if err := json.NewDecoder(r.Body).Decode(&tokenPayload); err != nil {
		http.Error(w, "Erreur lors de la lecture du corps de la demande", http.StatusBadRequest)
		return
	}

	tokenString := tokenPayload.Token
	log.Print("TOKEN STRING ", tokenString)

	// Validate and decode the JWT token to get the user's ID
	userID, err := validateAndExtractClaims(tokenString)
	if err != nil {
		http.Error(w, "Invalid JWT token", http.StatusUnauthorized)
		return
	}

	// Fetch the user from the data store
	user, err := getUserByID(userID)
	if err != nil {
		http.Error(w, "Error fetching user", http.StatusInternalServerError)
		return
	}

	var finalUser models.User
	finalUser.Email = user.Email
	finalUser.Username = user.Username
	finalUser.ID = user.ID

	// Respond with the user data in JSON format
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(finalUser)
}

// validateAndExtractClaims validates the JWT token and extracts claims
func validateAndExtractClaims(tokenString string) (int, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Validate the signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(_env.JwtSecret), nil
	})

	if err != nil {
		return 0, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return 0, fmt.Errorf("Invalid token claims")
	}

	userIDFloat, ok := claims["sub"].(float64)
	if !ok {
		return 0, fmt.Errorf("Invalid token claims")
	}

	// Convert the user ID to an integer
	userID := int(userIDFloat)
	log.Println("User ID:", userID)
	return userID, nil

}

// getUserByID retrieves a user from the data store by ID
func getUserByID(userID int) (*models.User, error) {
	userKey := fmt.Sprintf("users:%d", userID)
	userJSON, err := server.Client.Get(context.Background(), userKey).Result()
	if err != nil {
		return nil, err
	}

	var user models.User
	err = json.Unmarshal([]byte(userJSON), &user)
	if err != nil {
		return nil, err
	}

	return &user, nil
}
