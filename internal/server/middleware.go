package server

import (
	"errors"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/keyauth"
)

var (
	ErrNotEnoughPerm = errors.New("You aren't authorized to perform this action.")
	PsshNotFound     = "pssh field can not be emtpy"
)

func errHandler(c *fiber.Ctx, err error) error {
	if err == keyauth.ErrMissingOrMalformedAPIKey {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": err.Error(),
		})
	}
	return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
		"error": err.Error(),
	})
}

func limitReched(c *fiber.Ctx) error {
	return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
		"error": "Too many requests, try again later",
	})
}

func (s *FiberServer) validateAPIKey(c *fiber.Ctx, key string) (bool, error) {
	c.Accepts(fiber.MIMEApplicationJSON)

	su, sudo, err := s.DB.Sudoer(key)
	if err != nil {
		return false, keyauth.ErrMissingOrMalformedAPIKey
	}

	if su != 1 {
		if sudo != 1 {
			return false, ErrNotEnoughPerm
		}
	}

	return true, nil
}

func (s *FiberServer) suChecker(c *fiber.Ctx, key string) (bool, error) {
	c.Accepts(fiber.MIMEApplicationJSON)

	su, _, err := s.DB.Sudoer(key)
	if err != nil {
		return false, keyauth.ErrMissingOrMalformedAPIKey
	}

	if su != 1 {
		return false, ErrNotEnoughPerm
	}

	return true, nil
}
