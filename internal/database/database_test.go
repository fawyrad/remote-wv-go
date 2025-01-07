package database

import (
	"database/sql"
	"testing"
)

func TestOP(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	s := &service{db: db}

	t.Run("op passkey", func(t *testing.T) {
		_, err := db.Exec(`
		INSERT INTO sudoers (passkey, sudoer, super_user) VALUES
		('test_passkey', 1, 1),
		('test_passkey2', 1, 0),
    	('test_passkey3', 1, 1)
		`)
		if err != nil {
			t.Fatalf("Failed to insert test data: %v", err)
		}
		sudoers, err := s.OP()
		if err != nil {
			t.Fatalf("Error from OP: %v", err)
		}
		if len(sudoers) != 2 {
			t.Errorf("want 2, got: %d", len(sudoers))
		}

		for _, sudoer := range sudoers {
			if sudoer.Passkey == "" {
				t.Errorf("no sudoers in db")
			}
		}
	})

	t.Run("sudoers", func(t *testing.T) {
		_, sudoer, err := s.Sudoer("test_passkey2")
		if err != nil {
			t.Errorf("Failed to fetch passkey bearer: %v", err)
		}
		if sudoer != 1 {
			t.Error("user is no sudoer")
		}
	})

}

func setupTestDB(t testing.TB) *sql.DB {
	t.Helper()

	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS sudoers (
			passkey TEXT,
			sudoer INTEGER,
			super_user INTEGER
		)
		`)
	if err != nil {
		t.Fatalf("Failed to create table: %v", err)
	}
	return db
}
