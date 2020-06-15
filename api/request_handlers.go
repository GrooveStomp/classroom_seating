package main

import (
	"database/sql"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	"github.com/Masterminds/squirrel"
	"github.com/davecgh/go-spew/spew"
	"golang.org/x/crypto/bcrypt"
)

func CreateUser(w http.ResponseWriter, r *http.Request) {
	signup := struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}{}

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Print(err)
		http.Error(w, "Can't read request body", http.StatusBadRequest)
	}

	err = json.Unmarshal(body, &signup)
	if err != nil {
		log.Print(err)
		http.Error(w, "Can't unmarshal request body", http.StatusBadRequest)
	}

	encryptedPass, err := bcrypt.GenerateFromPassword([]byte(signup.Password), bcrypt.MinCost)
	if err != nil {
		log.Print(err)
		http.Error(w, "Can't encrypt password", http.StatusInternalServerError)
		return
	}

	newUser := User{
		Username: signup.Username,
		Password: encryptedPass,
	}

	query := psql.Insert("users").
		Columns("username", "password").
		Values(newUser.Username, newUser.Password).
		Suffix("RETURNING id").
		RunWith(db)

	err = query.Scan(&newUser.Id)
	if err != nil {
		log.Print(err)
		http.Error(w, "Can't create new user", http.StatusInternalServerError)
		return
	}

	querySel := psql.Select("id,username,created_at,updated_at").
		From("users").
		Where("id = ?", newUser.Id).
		RunWith(dbCache)

	err = querySel.Scan(&newUser.Id, &newUser.Username, &newUser.CreatedAt, &newUser.UpdatedAt)
	if err != nil {
		log.Print(err)
		http.Error(w, "Error fetching user", http.StatusInternalServerError)
		return
	}

	out, err := json.MarshalIndent(newUser, "", "    ")
	if err != nil {
		log.Print(err)
		http.Error(w, "Can't marshal response", http.StatusInternalServerError)
	}

	fmt.Fprintln(w, string(out))
}

func Login(w http.ResponseWriter, r *http.Request) {
	login := struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}{}

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Print(err)
		http.Error(w, "Can't read request body", http.StatusBadRequest)
	}

	err = json.Unmarshal(body, &login)
	if err != nil {
		log.Print(err)
		http.Error(w, "Can't unmarshal request body", http.StatusBadRequest)
	}

	spew.Dump(login)

	query := psql.Select("id,username,password").
		From("users").
		Where("username = ?", login.Username).
		//		Where("password = ?", encryptedPass).
		Where("deleted_at IS NULL").
		RunWith(dbCache)

	user := User{}
	err = query.Scan(&user.Id, &user.Username, &user.Password)
	if err != nil || !user.Id.Valid {
		log.Print(err)
		http.Error(w, "Couldn't find user", http.StatusNotFound)
		return
	}

	err = bcrypt.CompareHashAndPassword(user.Password, []byte(login.Password))
	if err != nil {
		log.Print("Password didn't match")
		http.Error(w, "Couldn't find user", http.StatusNotFound)
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

	// TODO: Don't do this - allow multiple simultaneous logins from different devices.
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

	outData := struct {
		AuthToken string `json:"auth_token"`
	}{
		AuthToken: authToken,
	}

	out, err := json.MarshalIndent(outData, "", "    ")
	if err != nil {
		log.Print(err)
		http.Error(w, "Can't marshal response", http.StatusInternalServerError)
	}

	fmt.Fprintln(w, string(out))
}

func Logout(w http.ResponseWriter, r *http.Request) {
	userId := r.Context().Value("userId").(string)

	query := psql.Update("authentications").
		SetMap(squirrel.Eq{"deleted_at": time.Now()}).
		Where("user_id = ?", userId).
		Where("deleted_at IS NULL").
		RunWith(db)

	err := query.Scan()
	if err != nil && err != sql.ErrNoRows {
		log.Printf("here %v", err)
		http.Error(w, "Couldn't clear authentications", http.StatusInternalServerError)
		return
	}

	log.Print("Logged out")
}

//-- Private, internal helpers.

func fifteenMinutesBefore(t time.Time) time.Time {
	return t.Add(-time.Minute * 15)
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
