package pkg

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"os"

	"github.com/joybiswas007/remote-wv-go/internal/widevine"
)

func GetCDM(pssh string) (*widevine.CDM, error) {
	clientIDPath := os.Getenv("WV_CLIENT_ID")
	privateKeyPath := os.Getenv("WV_PRIVATE_KEY")

	if clientIDPath == "" || privateKeyPath == "" {
		return nil, errors.New("failed to load widevine client_id or private_key")
	}

	clientID, err := readAsByte(clientIDPath)
	if err != nil {
		return nil, err
	}

	privateKey, err := readAsByte(privateKeyPath)
	if err != nil {
		return nil, err
	}
	initData, err := base64.StdEncoding.DecodeString(pssh)
	if err != nil {
		return nil, err
	}
	cdm, err := widevine.NewCDM(string(privateKey), clientID, initData)
	if err != nil {
		return nil, err
	}
	return &cdm, nil
}

// readAsByte() read file as byte and return the byte
func readAsByte(filename string) ([]byte, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		return nil, err
	}

	bs := make([]byte, stat.Size())
	_, err = file.Read(bs)

	if err != nil {
		return nil, err
	}

	return bs, nil
}

// GeneratePasskey generates random 16 bytes base32 token
func GeneratePasskey() (string, error) {
	randomBytes := make([]byte, 16)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return "", err
	}
	token := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(randomBytes)
	return token, nil
}
