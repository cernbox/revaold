package office_engine

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

func (cm *Manager) GetOfficeEngine(username string) (string, error) {
	var office string
	query := "select username, office from cbox_office_engine where username=?"
	if err := cm.db.QueryRow(query, username).Scan(&username, &office); err != nil {

		if err == sql.ErrNoRows {
			return "microsoft", nil
		}

		fmt.Println(err)
		return "", err
	}
	return office, nil
}

func (cm *Manager) SetOfficeEngine(username string, office string) error {

	if !cm.ValidOffice(office) {
		return errors.New("Invalid office engine")
	}

	query := "select username, office from cbox_office_engine where username=?"
	if err := cm.db.QueryRow(query, username).Scan(); err != nil && err != sql.ErrNoRows {
		// entry exists update it
		stmtString := "update cbox_office_engine set office=? where username=? "
		stmt, err := cm.db.Prepare(stmtString)
		if err != nil {
			return err
		}

		_, err = stmt.Exec(office, username)
		if err != nil {
			return err
		}
	} else {
		// entry does not exit we create one
		query := "insert into cbox_office_engine(username, office) values(?, ?)"
		stmt, err := cm.db.Prepare(query)
		if err != nil {
			return err
		}

		_, err = stmt.Exec(username, office)
		if err != nil {
			return err
		}
	}
	return nil
}

func (cm *Manager) ValidOffice(office string) bool {
	for _, value := range []string{"onlyoffice", "microsoft"} {
		if value == office {
			return true
		}
	}
	return false
}
