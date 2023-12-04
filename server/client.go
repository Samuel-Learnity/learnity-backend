package server

import (
	"context"
	"github.com/redis/go-redis/v9"
	"log"
)

var Client *redis.Client

func Init() {
	// Connexion à Redis
	Client = redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "",
		DB:       0,
	})

	// Vérifiez la connexion
	_, err := Client.Ping(context.Background()).Result()
	if err != nil {
		log.Fatal("Erreur de connexion à Redis:", err)
	} else {
		log.Print("Ping")
	}
}
