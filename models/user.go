package models

type User struct {
	ID             int    `json:"id"`
	Username       string `json:"username"`
	Email          string `json:"email"`
	Password       string `json:"password"`       // Mot de passe non chiffré (utilisé lors de l'inscription)
	HashedPassword string `json:"hashedPassword"` // Mot de passe chiffré (utilisé lors de la connexion)
	Token          string `json:"token,omitempty"`
	TokenExpireAt  int64  `json:"token_expire_at,omitempty"`
}
