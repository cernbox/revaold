package canary

import (
	"database/sql"
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

func (cm *Manager) isAdopter(username string) bool {
	var adopter string
	query := "select username,adopter from cbox_canary where username=?"
	if err := cm.db.QueryRow(query, username).Scan(&username, &adopter); err != nil {
		return false
	}
	if adopter == "yes" {
		return true
	}
	return false
}
