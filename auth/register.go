package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"learnity-backend/models"
	_ "learnity-backend/models"
	"learnity-backend/server"
	"net/http"
)

func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Méthode non autorisée", http.StatusMethodNotAllowed)
		return
	}

	decoder := json.NewDecoder(r.Body)
	var newUser models.User

	err := decoder.Decode(&newUser)
	if err != nil {
		http.Error(w, "Erreur lors de la lecture du corps de la demande", http.StatusBadRequest)
		return
	}

	// Vérifier si l'utilisateur existe déjà (simulé pour cet exemple)
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

	newUser.ID = int(userID)

	// Ajouter l'ID utilisateur à l'ensemble "users" dans Redis
	err = server.Client.SAdd(context.Background(), "users", newUser.Email).Err()
	if err != nil {
		http.Error(w, "Erreur lors de l'ajout de l'ID utilisateur à l'ensemble dans Redis", http.StatusInternalServerError)
		return
	}

	// Convertir l'utilisateur en JSON et le stocker dans Redis
	userJSONBytes, err := json.Marshal(newUser)
	if err != nil {
		http.Error(w, "Erreur lors de la sérialisation de l'utilisateur en JSON", http.StatusInternalServerError)
		return
	}

	// Convertir le tableau d'octets en chaîne de caractères
	userJSON := string(userJSONBytes)

	key := fmt.Sprintf("users:%s", newUser.Email)
	err = server.Client.Set(context.Background(), key, userJSON, 0).Err()
	if err != nil {
		http.Error(w, "Erreur lors de la sauvegarde de l'utilisateur dans Redis", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
}
