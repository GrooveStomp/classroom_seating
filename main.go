package main

import (
	"database/sql"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/BurntSushi/toml"
	"github.com/Masterminds/squirrel"
	"github.com/julienschmidt/httprouter"
	"github.com/justinas/alice"

	mw "github.com/GrooveStomp/classroom_seating/internal/middleware"
	jsoniter "github.com/json-iterator/go"
	_ "github.com/lib/pq"
)

var (
	db      *sql.DB
	psql    squirrel.StatementBuilderType
	dbCache squirrel.DBProxyBeginner
	json    jsoniter.API
)

func main() {
	json = jsoniter.ConfigCompatibleWithStandardLibrary

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

	mwareNoAuth := alice.New(mw.Cors, mw.Throttle, mw.Log)
	mwareAuth := mwareNoAuth.Append(mw.MakeAuthenticate(psql, db))

	router := httprouter.New()
	router.Handler("POST", "/users", mwareNoAuth.ThenFunc(CreateUser))
	router.Handler("POST", "/login", mwareNoAuth.ThenFunc(Login))
	router.Handler("GET", "/logout", mwareAuth.ThenFunc(Logout))

	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%v", cfg.Server.Port), router))
}
