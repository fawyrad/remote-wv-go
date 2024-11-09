package server

import (
	"os"

	"github.com/gofiber/fiber/v2"
	"github.com/joybiswas007/remote-wv-go/internal/database"
)

type FiberServer struct {
	*fiber.App

	DB database.Service
}

func New() *FiberServer {
	appName := os.Getenv("APP_NAME")
	if appName == "" {
		appName = "remote-wv-go"
	}
	server := &FiberServer{
		App: fiber.New(fiber.Config{
			ServerHeader: appName,
			AppName:      appName,
		}),

		DB: database.New(),
	}

	return server
}
