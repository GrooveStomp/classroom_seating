package common

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
	Id        string    `db:"id" json:"id"`
	Username  string    `db:"username" json:"username"`
	Password  []byte    `db:"password" json:"-"`
	CreatedAt time.Time `db:"created_at" json:"createdAt"`
	UpdatedAt time.Time `db:"updated_at" json:"updatedAt"`
	DeletedAt null.Time `db:"deleted_at" json:"-"`
}

type Session struct {
	Id          string    `db:"id" json:"id"`
	UserId      string    `db:"user_id" json:"userId"`
	ServerToken string    `db:"server_token" json:"serverToken"`
	ClientToken string    `db:"client_token" json:"clientToken"`
	ExpiresAt   time.Time `db:"expires_at" json:"expiresAt"`
	CreatedAt   time.Time `db:"created_at" json:"createdAt"`
	UpdatedAt   time.Time `db:"updated_at" json:"updatedAt"`
}

type PageData struct {
	Authenticated bool
	Title         string
}

type Cookier interface {
	Cookie(name string) (*http.Cookie, error)
}
