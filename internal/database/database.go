package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	_ "github.com/joho/godotenv/autoload"
	_ "github.com/mattn/go-sqlite3"
)

// Service represents a service that interacts with a database.
type Service interface {
	//Insert the pssh and key into db
	Insert(pssh, key string) error

	//Get returns the key associated with the pssh
	Get(pssh string) (*Key, error)

	//SudoSU add user to sudoers list
	SudoSU(passkey string, superUser, sudoer int) error

	//Sudoer check whether a user is super_user or sudoer
	Sudoer(passkey string) (super_user, sudoer int, err error)

	//Revoke revokes user access
	Revoke(passkey string) error

	// Close terminates the database connection.
	// It returns an error if the connection cannot be closed.
	Close() error
}

type service struct {
	db *sql.DB
}

type Key struct {
	CreatedAt     time.Time `json:"-"`              // "-" for not including in result
	PSSH          string    `json:"pssh,omitempty"` //PSSH
	DecryptionKey string    `json:"key,omitempty"`  //DecryptionKey
}

type Sudoer struct {
	Passkey   string `json:"passkey"`
	SuperUser int    `json:"super_user"`
	Sudoer    int    `json:"sudoer"`
}

var (
	dburl      = os.Getenv("WV_DB_URL")
	dbInstance *service
)

func New() Service {
	// Reuse Connection
	if dbInstance != nil {
		return dbInstance
	}

	db, err := sql.Open("sqlite3", dburl)
	if err != nil {
		// This will not be a connection error, but a DSN parse error or
		// another initialization error.
		log.Fatal(err)
	}

	createKeyTableSQL := `CREATE TABLE IF NOT EXISTS widevine_keys (
			      id INTEGER PRIMARY KEY AUTOINCREMENT,
	      		      pssh TEXT NOT NULL,
			      key TEXT NOT NULL,
           		      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		      );`

	createSudoersTableSQL := `CREATE TABLE IF NOT EXISTS sudoers (
				  id INTEGER PRIMARY KEY AUTOINCREMENT,
				  passkey TEXT NOT NULL,
				  super_user INTEGER DEFAULT 0,
				  sudoer INTEGER DEFAULT 0,
				  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
			);`
	if _, err := db.Exec(createKeyTableSQL); err != nil {
		log.Fatalf("failed to create key table :%v", err)
	}
	if _, err := db.Exec(createSudoersTableSQL); err != nil {
		log.Fatalf("failed to create sudoers table: %v", err)
	}

	dbInstance = &service{
		db: db,
	}
	return dbInstance
}

// Create new users
func (s *service) SudoSU(passkey string, superUser, sudoer int) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stmt, err := s.db.PrepareContext(ctx, "INSERT INTO sudoers(passkey, super_user, sudoer) VALUES(?, ?, ?)")
	if err != nil {
		return fmt.Errorf("failed to prepare the insert statement: %s", err)
	}
	defer stmt.Close()

	_, err = stmt.ExecContext(ctx, passkey, superUser, sudoer)
	if err != nil {
		return fmt.Errorf("failed to execute the insert statement %v", err)
	}

	return nil
}

// Sudoer returns types of persmission users have
func (s *service) Sudoer(passkey string) (super_user, sudoer int, err error) {
	query := `SELECT super_user, sudoer
		  FROM sudoers
		  WHERE sudoers.passkey = $1`

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = s.db.QueryRowContext(ctx, query, passkey).Scan(&super_user, &sudoer)
	if err != nil {
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return 0, 0, errors.New("user is not on the sudoers list")
		default:
			return 0, 0, err
		}
	}

	return super_user, sudoer, nil
}

// Revoke revokes user access
func (s *service) Revoke(passkey string) error {
	query := `UPDATE sudoers SET sudoer = 0, super_user = 0 WHERE passkey = $1`

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if _, err := s.db.ExecContext(ctx, query, passkey); err != nil {
		return err
	}
	return nil
}

// Insert inserts pssh and key  into the SQLite database and returns the result.
func (s *service) Insert(pssh, key string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stmt, err := s.db.PrepareContext(ctx, "INSERT INTO widevine_keys(pssh, key) VALUES(?, ?)")
	if err != nil {
		return fmt.Errorf("failed to prepare the insert statement: %v", err)
	}
	defer stmt.Close()

	_, err = stmt.ExecContext(ctx, pssh, key)
	if err != nil {
		return fmt.Errorf("failed to execute the insert statement: %v", err)
	}

	return nil
}

// Get returns the decryption key associated with the given pssh
func (s *service) Get(pssh string) (*Key, error) {
	query := `
		SELECT DISTINCT pssh, key
		FROM widevine_keys
		WHERE widevine_keys.pssh = $1
		`

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var key Key
	err := s.db.QueryRowContext(ctx, query, pssh).Scan(
		&key.PSSH,
		&key.DecryptionKey,
	)
	if err != nil {
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return nil, errors.New("record not found")
		default:
			return nil, err
		}
	}
	return &key, nil
}

// Close closes the database connection.
// It logs a message indicating the disconnection from the specific database.
// If the connection is successfully closed, it returns nil.
// If an error occurs while closing the connection, it returns the error.
func (s *service) Close() error {
	log.Printf("Disconnected from database: %s", dburl)
	return s.db.Close()
}
