package server

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/keyauth"
	"github.com/gofiber/fiber/v2/middleware/limiter"
	"github.com/gofiber/storage/sqlite3"
	"github.com/joybiswas007/remote-wv-go/internal/pkg"
	"github.com/joybiswas007/remote-wv-go/internal/widevine"
)

type input struct {
	PSSH      string `json:"pssh,omitempty"`
	Challenge string `json:"challenge,omitempty"`
	License   string `json:"license,omitempty"`
	Passkey   string `json:"passkey,omitempty"`
	Quantity  int    `json:"quantity,omitempty"`
	SuperUser int    `json:"super_user,omitempty"`
	Sudoer    int    `json:"sudoer,omitempty"`
}

var (
	PsshNotFound = errors.New("pssh field can not be emtpy")
)

func errHandler(c *fiber.Ctx, err error) error {
	if err == keyauth.ErrMissingOrMalformedAPIKey {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": err.Error(),
		})
	}
	return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": err.Error()})
}

func (s *FiberServer) RegisterFiberRoutes() {
	v1 := s.Group("/v1", keyauth.New(keyauth.Config{
		KeyLookup:    "key:passkey",
		Validator:    s.ValidateAPIKey,
		ErrorHandler: errHandler,
	}))

	maxReqLimit := 100
	max := os.Getenv("MAX_REQ_LIMIT")
	if max != "" {
		value, err := strconv.Atoi(max)
		if err != nil {
			fmt.Printf("Warning: MAX_REQ_LIMIT is not a valid integer, using default value %d", maxReqLimit)
		}
		maxReqLimit = value
	}

	storage := sqlite3.New()

	v1.Use(limiter.New(limiter.Config{
		Max:        maxReqLimit,
		Expiration: 60 * time.Second,
		LimitReached: func(c *fiber.Ctx) error {
			return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
				"error": "Too many requests, try again later",
			})
		},
		Storage: storage,
	}))

	v1.Get("/", func(c *fiber.Ctx) error { return c.Status(fiber.StatusOK).JSON(fiber.Map{"hello": "world"}) })
	v1.Post("/challenge", s.ChallengeHandler)
	v1.Post("/key", s.KeyHandler)
	v1.Post("/arsenal/key", s.ArsenalKeyHandler)

	su := s.Group("/su", keyauth.New(keyauth.Config{
		KeyLookup:    "key:passkey",
		Validator:    s.SUChecker,
		ErrorHandler: errHandler,
	}))
	su.Post("/passkey", s.AddSudoerHandler)
	su.Post("/revoke", s.RevokeSudoerHandler)
}

func (s *FiberServer) ChallengeHandler(c *fiber.Ctx) error {
	i := new(input)
	if err := c.BodyParser(i); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	if i.PSSH == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": PsshNotFound,
		})
	}

	cdm, err := pkg.GetCDM(i.PSSH)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	licenseRequest, err := cdm.GetLicenseRequest()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
	}
	resp := fiber.Map{
		"challenge": licenseRequest,
		"pssh":      i.PSSH,
	}
	return c.Status(fiber.StatusOK).JSON(resp)
}

func (s *FiberServer) KeyHandler(c *fiber.Ctx) error {
	i := new(input)
	if err := c.BodyParser(i); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
	}
	if i.Challenge == "" || i.License == "" || i.PSSH == "" {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": "license or challange or pssh field can not be empty",
		})
	}
	cdm, err := pkg.GetCDM(i.PSSH)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	licenseRequest, err := base64.StdEncoding.DecodeString(i.Challenge)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	decodedLicense, err := base64.StdEncoding.DecodeString(i.License)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	keys, err := cdm.GetLicenseKeys(licenseRequest, decodedLicense)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	decryptionKey := ""

	for _, key := range keys {
		if key.Type == widevine.License_KeyContainer_CONTENT {
			decryptionKey += hex.EncodeToString(key.ID) + ":" + hex.EncodeToString(key.Value)
		}
	}

	if err := s.DB.Insert(i.PSSH, decryptionKey); err != nil {
		log.Printf("%s", err.Error())
	}

	return c.Status(http.StatusOK).JSON(fiber.Map{
		"key":  decryptionKey,
		"pssh": i.PSSH,
	})
}

func (s *FiberServer) ArsenalKeyHandler(c *fiber.Ctx) error {
	i := new(input)
	if err := c.BodyParser(i); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
	}
	if i.PSSH == "" {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": PsshNotFound,
		})
	}

	key, err := s.DB.Get(i.PSSH)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"key":  key.DecryptionKey,
		"pssh": key.PSSH,
	})
}

func (s *FiberServer) AddSudoerHandler(c *fiber.Ctx) error {
	i := new(input)
	i.Quantity = 1
	if err := c.BodyParser(i); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	var passkeys []string
	for j := 1; j <= i.Quantity; j++ {
		pk, err := pkg.GeneratePasskey()
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": err.Error(),
			})
		}

		passkeys = append(passkeys, pk)

		if err := s.DB.SudoSU(pk, i.SuperUser, i.Sudoer); err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": err.Error(),
			})
		}
	}

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"success":  true,
		"passkeys": passkeys,
		"message":  fmt.Sprintf("Yay! your %d keys has been generated", i.Quantity),
	})

}

func (s *FiberServer) RevokeSudoerHandler(c *fiber.Ctx) error {
	i := new(input)
	if err := c.BodyParser(i); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": err.Error(),
		})
	}
	if i.Passkey == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "In order to revoke access, you need pass the passkey.",
		})
	}

	if err := s.DB.Revoke(i.Passkey); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"success": true,
		"message": "access has been revoked",
	})
}
