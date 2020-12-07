package canary

import (
	"database/sql"
	"errors"
	"fmt"

	_ "github.com/go-sql-driver/mysql"
)

type Manager struct {
	db *sql.DB
}

type Options struct {
	DBUsername, DBPassword, DBHost, DBName string
	DBPort                                 int
}

func New(opts *Options) *Manager {
	db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%d)/%s", opts.DBUsername, opts.DBPassword, opts.DBHost, opts.DBPort, opts.DBName))
	if err != nil {
		panic(err)
	}

	return &Manager{db: db}
}

func (cm *Manager) GetVersion(username string) string {
	var adopter string
	query := "select username, adopter from cbox_canary where username=?"
	if err := cm.db.QueryRow(query, username).Scan(&username, &adopter); err != nil {
		fmt.Println(err)
		return "production"
	}

	// For old data...
	if adopter == "yes" {
		return "canary"
	} else if adopter == "no" || adopter == "" {
		return "production"
	}

	return adopter
}

func (cm *Manager) SetVersion(username, version string) error {

	valid := Find([]string{"production", "canary", "ocis"}, version)
	if !valid {
		return errors.New("Invalid option")
	}

	query := "INSERT INTO cbox_canary (username, adopter) VALUES (?, ?) ON DUPLICATE KEY UPDATE adopter = ?"
	stmt, err := cm.db.Prepare(query)
	if err != nil {
		return err
	}

	_, err = stmt.Exec(username, version, version)
	if err != nil {
		return err
	}

	return nil
}

func Find(slice []string, val string) bool {
	for _, item := range slice {
		if item == val {
			return true
		}
	}
	return false
}
