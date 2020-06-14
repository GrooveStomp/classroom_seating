package main

import (
	"net/http"
	"time"

	"gopkg.in/guregu/null.v4"
)

type Config struct {
	Database DatabaseConfig   `toml:"database"`
	Server   HttpServerConfig `toml:"http_server"`
}

type DatabaseConfig struct {
	Host     string
	Port     uint
	Name     string
	User     string
	Password string
}

type HttpServerConfig struct {
	Port uint
}

type User struct {
	Id        null.String `db:"id" json:"id"`
	Username  string      `json:"username"`
	Password  []byte      `json:"-"`
	CreatedAt time.Time   `db:"created_at" json:"created_at"`
	UpdatedAt time.Time   `db:"updated_at" json:"updated_at"`
	DeletedAt null.Time   `db:"deleted_at" json:"-"`
}

type PageData struct {
	Authenticated bool
	Title         string
}

type Cookier interface {
	Cookie(name string) (*http.Cookie, error)
}
