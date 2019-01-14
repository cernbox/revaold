package project_manager_db

import (
	"context"
	"fmt"

	"github.com/cernbox/revaold/api"

	"database/sql"
	_ "github.com/go-sql-driver/mysql"
)

type projectManager struct {
	db *sql.DB
}

func New(dbUsername, dbPassword, dbHost string, dbPort int, dbName string, vfs api.VirtualStorage) api.ProjectManager {
	db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%d)/%s", dbUsername, dbPassword, dbHost, dbPort, dbName))
	if err != nil {
		panic(err)
	}

	return &projectManager{db: db}
}

func (pm *projectManager) GetProject(ctx context.Context, projectName string) (*api.Project, error) {
	var (
		owner string
		path  string
	)

	query := "select eos_relative_path, project_owner from cernbox_project_mapping where project_name=?"
	if err := pm.db.QueryRow(query, projectName).Scan(&path, &owner); err != nil {
		if err == sql.ErrNoRows {
			return nil, api.NewError(api.ProjectNotFoundErrorCode)
		}
		return nil, err
	}

	adminGroup := getAdminGroup(projectName)
	writersGroup := getWritersGroup(projectName)
	readersGroup := getReadersGroup(projectName)

	project := &api.Project{Name: projectName, Owner: owner, Path: path, AdminGroup: adminGroup, ReadersGroup: readersGroup, WritersGroup: writersGroup}
	return project, nil

}

func getAdminGroup(name string) string   { return "cernbox-project-" + name + "-admins" }
func getReadersGroup(name string) string { return "cernbox-project-" + name + "-readers" }
func getWritersGroup(name string) string { return "cernbox-project-" + name + "-writers" }

func (pm *projectManager) GetAllProjects(ctx context.Context) ([]*api.Project, error) {
	query := "select project_name, project_owner, eos_relative_path from cernbox_project_mapping"
	rows, err := pm.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var (
		name  string
		owner string
		path  string
	)

	projects := []*api.Project{}
	for rows.Next() {
		err := rows.Scan(&name, &owner, &path)
		if err != nil {
			return nil, err
		}

		adminGroup := getAdminGroup(name)
		writersGroup := getWritersGroup(name)
		readersGroup := getReadersGroup(name)

		project := &api.Project{Owner: owner, Path: path, Name: name, AdminGroup: adminGroup, ReadersGroup: readersGroup, WritersGroup: writersGroup}
		projects = append(projects, project)

	}

	err = rows.Err()
	if err != nil {
		return nil, err
	}

	return projects, nil
}
