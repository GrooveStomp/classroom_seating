package main

import (
	"fmt"
	"github.com/BurntSushi/toml"
	"github.com/husobee/vestigo"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	"io/ioutil"
	"log"
	"net/http"
)

var (
	db *sqlx.DB
)

func main() {
	var (
		cfg Config
	)
	router := vestigo.NewRouter()

	dat, err := ioutil.ReadFile("cfg.toml")
	if err != nil {
		log.Fatal(err)
	}
	strDat := string(dat)

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

	db, err = sqlx.Connect("postgres", dbString)
	if err != nil {
		log.Fatalln(err)
	}

	db.MustExec("DELETE FROM users")

	router.Get("/", ShowRootHandler)
	router.Get("/register", ShowRegistrationHandler)
	router.Post("/users", CreateUserHandler)

	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%v", cfg.Server.Port), router))
}
