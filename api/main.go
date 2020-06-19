package main

import (
	"database/sql"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/BurntSushi/toml"
	"github.com/Masterminds/squirrel"
	"github.com/julienschmidt/httprouter"
	"github.com/justinas/alice"
	"github.com/rs/cors"

	c "github.com/GrooveStomp/classroom_seating/internal/common"
	mw "github.com/GrooveStomp/classroom_seating/internal/middleware"
	jsoniter "github.com/json-iterator/go"
	_ "github.com/lib/pq"
	log "github.com/sirupsen/logrus"
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

	var cfg c.Config
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

	mwareNoAuth := alice.New(mw.Throttle, mw.Log)
	mwareAuth := mwareNoAuth.Append(mw.MakeAuthenticate(psql, db))

	router := httprouter.New()
	router.Handler("POST", "/users", mwareNoAuth.ThenFunc(CreateUser))
	router.Handler("POST", "/login", mwareNoAuth.ThenFunc(Login))
	router.Handler("GET", "/logout", mwareAuth.ThenFunc(Logout))

	c := cors.New(cors.Options{
		Debug:          true,
		AllowedHeaders: []string{"Content-Type", "X-Client-Token", "X-Request-ID"},
	})

	log.Fatal(http.ListenAndServe(
		fmt.Sprintf(":%v", cfg.Server.Port),
		c.Handler(router),
	))
}
