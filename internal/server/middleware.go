package server

import (
	"errors"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/keyauth"
)

var (
	ErrNotEnoughPerm = errors.New("You aren't authorized to perform this action.")
)

func (s *FiberServer) ValidateAPIKey(c *fiber.Ctx, key string) (bool, error) {
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

func (s *FiberServer) SUChecker(c *fiber.Ctx, key string) (bool, error) {
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
