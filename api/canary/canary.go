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

func (cm *Manager) IsAdopter(username string) bool {
	var adopter string
	query := "select username,adopter from cbox_canary where username=?"
	if err := cm.db.QueryRow(query, username).Scan(&username, &adopter); err != nil {
		fmt.Println(err)
		return false
	}
	fmt.Println(adopter)
	if adopter == "yes" {
		return true
	}
	return false
}

func (cm *Manager) SetStatus(username string, adopter bool) error {
	isAdopter := "no"
	if adopter {
		isAdopter = "yes"
	}

	query := "select username,adopter from cbox_canary where username=?"
	if err := cm.db.QueryRow(query, username).Scan(); err != nil  && err != sql.ErrNoRows {
		// entry exists update it
		stmtString := "update cbox_canary set adopter=? where username=? "
		stmt, err := cm.db.Prepare(stmtString)
		if err != nil {
			return err
		}

		_, err = stmt.Exec(isAdopter, username)
		if err != nil {
			return err
		}
	} else {
		// entry does not exit we create one
		query := "insert into cbox_canary(username, adopter) values(?, ?)"
		stmt, err := cm.db.Prepare(query)
		if err != nil {
			return err
		}

		_, err = stmt.Exec(username, isAdopter)
		if err != nil {
			return err
		}
	}
	return nil
}
