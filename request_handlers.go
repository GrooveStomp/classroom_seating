package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"text/template"
	"time"

	"github.com/Masterminds/squirrel"
	"golang.org/x/crypto/bcrypt"
)

func ShowRoot(w http.ResponseWriter, r *http.Request) {
	logHandlerIntro(r.Method, r.URL.Path, r.Form)
	renderPage(w, r, "templates/index.tmpl", "Home")
}

func ShowRegistration(w http.ResponseWriter, r *http.Request) {
	logHandlerIntro(r.Method, r.URL.Path, r.Form)
	renderPage(w, r, "templates/registration.tmpl", "Registration")
}

func ShowLogin(w http.ResponseWriter, r *http.Request) {
	logHandlerIntro(r.Method, r.URL.Path, r.Form)
	renderPage(w, r, "templates/login.tmpl", "Login")
}

func CreateUser(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	logHandlerIntro(r.Method, r.URL.Path, r.Form)

	password := r.FormValue("password")
	encryptedPass, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		log.Println(err)
		http.Error(w, "Error registering", http.StatusInternalServerError)
		return
	}

	newUser := User{
		Username: r.FormValue("username"),
		Password: encryptedPass,
	}

	query := psql.Insert("users").
		Columns("username", "password").
		Values(newUser.Username, newUser.Password).
		Suffix("RETURNING ?", "id").
		RunWith(db)

	err = query.Scan(&newUser.Id)
	if err != nil {
		log.Println(err)
		http.Error(w, "Error registering", http.StatusInternalServerError)
		return
	}

	log.Printf("User added: %+v\n", newUser)
	fmt.Fprintln(w, "Success!")
}

func Login(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	logHandlerIntro(r.Method, r.URL.Path, r.Form)

	user := User{
		Username: r.FormValue("username"),
	}

	query := psql.Select("id,username,password").
		From("users").
		Where("username = ?", user.Username).
		Where("deleted_at IS NULL").
		RunWith(db)

	err := query.Scan(&user.Id, &user.Username, &user.Password)
	if err != nil || !user.Id.Valid {
		log.Printf("Couldn't find user: %v\n", err.Error())
		http.Error(w, "Error logging in", http.StatusNotFound)
		return
	}

	incomingPass := []byte(r.FormValue("password"))
	err = bcrypt.CompareHashAndPassword(user.Password, incomingPass)
	if err != nil {
		log.Printf("Password didn't match: %v\n", err.Error())
		http.Error(w, "Error logging in", http.StatusUnauthorized)
		return
	}

	// Already checked the case where this fails above.
	userId, _ := user.Id.Value()
	authToken, err := findLoginAuthToken(userId.(string))

	if err == nil {
		// We have an auth token that is still valid, let's use that.
		query := psql.Update("authentications").
			SetMap(squirrel.Eq{"updated_at": time.Now()}).
			Where("token = ?", authToken).
			Where("deleted_at IS NULL").
			Suffix("RETURNING id").
			RunWith(db)

		var _id int
		err = query.Scan(&_id)
		if err != nil {
			log.Printf("Couldn't update existing auth token: %#+v\n", err.Error())
			http.Error(w, "Error", http.StatusInternalServerError)
			return
		}
	} else {
		// Create a new authentication for this user.
		query := psql.Insert("authentications").
			Columns("user_id").
			Values(userId).
			Suffix("RETURNING token").
			RunWith(db)

		err = query.Scan(&authToken)
		if err != nil {
			log.Printf("Couldn't create new authentication: %v\n", err.Error())
			http.Error(w, "Error logging in", http.StatusInternalServerError)
			return
		}
	}

	// Invalidate all outstanding authentications for this user.
	updateQuery := psql.Update("authentications").
		SetMap(squirrel.Eq{"deleted_at": time.Now()}).
		Where("user_id = ?", userId).
		Where("deleted_at IS NULL").
		Where("token != ?", authToken).
		RunWith(db)

	err = updateQuery.Scan()
	if err != nil && err != sql.ErrNoRows {
		log.Printf("Couldn't delete outstanding authentications: %v\n", err.Error())
		http.Error(w, "Error logging in", http.StatusInternalServerError)
		return
	}

	cookie := &http.Cookie{
		Name:    "authtoken",
		Value:   authToken,
		Expires: time.Now().UTC().Add(time.Minute * 15),
	}
	http.SetCookie(w, cookie)

	log.Printf("Logged in as: %+v\n", user)
	fmt.Fprintln(w, "Success!")
}

func Logout(w http.ResponseWriter, r *http.Request) {
	logHandlerIntro(r.Method, r.URL.Path, r.Form)
	fmt.Fprintln(w, "Success!")

	userId, err := authenticate(r)
	if err != nil {
		log.Println(err)
		http.Error(w, "Couldn't authenticate", http.StatusBadRequest)
	}

	query := psql.Update("authentications").
		SetMap(squirrel.Eq{"deleted_at": time.Now()}).
		Where("user_id = ?", userId).
		Where("deleted_at IS NULL").
		RunWith(db)

	err = query.Scan()
	if err != nil && err != sql.ErrNoRows {
		log.Println(err)
		http.Error(w, "Couldn't clear authentications", http.StatusInternalServerError)
		return
	}
}

//-- Private, internal helpers.

func fifteenMinutesBefore(t time.Time) time.Time {
	return t.Add(-time.Minute * 15)
}

func logHandlerIntro(requestMethod, requestPath string, requestData url.Values) {
	log.Printf("%s %q: %+v\n", requestMethod, requestPath, requestData)
}

func authenticate(c Cookier) (string, error) {
	authCookie, err := c.Cookie("authtoken")
	if err != nil {
		return "", err
	}

	var userId string
	query := psql.Select("user_id").
		From("authentications").
		Where("token = ?", authCookie.Value).
		Where("deleted_at IS NULL").
		Where("updated_at > ?", fifteenMinutesBefore(time.Now())).
		RunWith(dbCache)

	err = query.Scan(&userId)
	if err != nil {
		log.Println(err)
		return "", err
	}

	log.Printf("Authenticated as: %v\n", userId)
	return userId, nil
}

func findLoginAuthToken(userId string) (string, error) {
	// Get the last authentication.
	var authToken string

	query := psql.Select("token").
		From("authentications").
		Where("user_id = ?", userId).
		Where("deleted_at IS NULL").
		Where("updated_at > ?", fifteenMinutesBefore(time.Now())).
		RunWith(dbCache)

	err := query.Scan(&authToken)
	if err != nil {
		return "", err
	}

	log.Printf("findLoginAuthToken: authToken: %s\n", authToken)
	return authToken, nil
}

func renderPage(w http.ResponseWriter, r *http.Request, templateName, title string) {
	userId, _ := authenticate(r)

	t := template.Must(
		template.ParseFiles(
			"templates/header.tmpl",
			"templates/navigation.tmpl",
			"templates/footer.tmpl",
			templateName))

	data := PageData{
		Title:         title,
		Authenticated: userId != "",
	}

	err := t.ExecuteTemplate(w, strings.ToLower(title), data)

	if err != nil {
		log.Println(err)
	}
}
