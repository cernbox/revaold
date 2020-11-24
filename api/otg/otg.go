package otg

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

func (cm *Manager) GetOTG() (string, error) {
	var message string
	query := "select message from cbox_otg limit 1"
	if err := cm.db.QueryRow(query).Scan(&message); err != nil {

		if err == sql.ErrNoRows {
			return "", nil
		}

		return "", err
	}
	return message, nil
}
