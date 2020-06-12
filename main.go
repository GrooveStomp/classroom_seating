package main

import (
	"database/sql"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	_ "github.com/lib/pq"

	"github.com/BurntSushi/toml"
	"github.com/Masterminds/squirrel"
	"github.com/husobee/vestigo"
)

var (
	db      *sql.DB
	psql    squirrel.StatementBuilderType
	dbCache squirrel.DBProxyBeginner
)

func main() {
	router := vestigo.NewRouter()

	dat, err := ioutil.ReadFile("cfg.toml")
	if err != nil {
		log.Fatal(err)
	}
	strDat := string(dat)

	var cfg Config
	if _, err := toml.Decode(strDat, &cfg); err != nil {
		log.Fatal(err)
	}

	dbString := fmt.Sprintf(
		"user=%v password=%v host=%v port=%v dbname=%v sslmode=disable",
		cfg.Database.User,
		cfg.Database.Password,
		cfg.Database.Host,
		cfg.Database.Port,
		cfg.Database.Name,
	)

	db, err = sql.Open("postgres", dbString)
	if err != nil {
		log.Fatalln(err)
	}

	err = db.Ping()
	if err != nil {
		log.Fatalf("Error opening database connection: %v", err.Error())
	}

	dbCache = squirrel.NewStmtCacheProxy(db)
	psql = squirrel.StatementBuilder.PlaceholderFormat(squirrel.Dollar)

	router.Get("/", ShowRoot)
	router.Get("/register", ShowRegistration)
	router.Get("/login", ShowLogin)
	router.Post("/users", CreateUser)
	router.Post("/login", Login)
	router.Get("/logout", Logout)

	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%v", cfg.Server.Port), router))
}
