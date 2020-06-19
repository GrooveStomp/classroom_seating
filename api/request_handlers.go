package main

import (
	"database/sql"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/Masterminds/squirrel"
	"github.com/davecgh/go-spew/spew"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/square/go-jose.v2/jwt"

	c "github.com/GrooveStomp/classroom_seating/internal/common"
	log "github.com/sirupsen/logrus"
	jose "gopkg.in/square/go-jose.v2"
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

	newUser := c.User{
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
	//-- Get data from the request -----------------------------------------------

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

	//-- Get data from the database to validate request data against -------------

	query := psql.Select("id,username,password").
		From("users").
		Where("username = ?", login.Username).
		//		Where("password = ?", encryptedPass).
		Where("deleted_at IS NULL").
		RunWith(dbCache)

	user := c.User{}
	err = query.Scan(&user.Id, &user.Username, &user.Password)
	if err != nil {
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

	//-- Create a new session for the user ---------------------------------------

	clientToken := r.Header.Get("X-Client-Token")
	if clientToken == "" {
		log.Info("X-Client-Token is empty")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	queryInsert := psql.Insert("sessions").
		Columns("user_id", "client_token").
		Values(user.Id, clientToken).
		Suffix("RETURNING id").
		RunWith(db)

	session := c.Session{}
	err = queryInsert.Scan(&session.Id)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Info("Couldn't create new session")
		http.Error(w, "Error logging in", http.StatusInternalServerError)
		return
	}

	query2 := psql.Select("user_id", "client_token", "server_token", "expires_at").
		From("sessions").
		Where("id = ?", session.Id).
		RunWith(dbCache)

	err = query2.Scan(&session.UserId, &session.ClientToken, &session.ServerToken, &session.ExpiresAt)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Info("Couldn't retrieve session")
		http.Error(w, "Error logging in", http.StatusInternalServerError)
		return
	}

	webToken, err := makeJwt(session)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Info("Couldn't make jwt")
		http.Error(w, "Error logging in", http.StatusInternalServerError)
		return
	}

	outData := struct {
		Jwt string `json:"jwt"`
	}{
		Jwt: webToken,
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

	// TODO: Need to use session ID
	query := psql.Update("sessions").
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

//-- Private, internal helpers -------------------------------------------------

// How it works:
// 1. Client generates a client token and does initial request.
// 2. Server generates a server token pair for the client token.
//    It stores this association.
//    It returns the server token symmetrically encrypted with the client token.
// 3. Client decrypts the server token and uses it to encrypt private data in subsequent requests.
//    The client must use private storage for the server token!
//    The client continues sending the client token with each request
//    The server will look up the server token for the specified client token.
//    "Private Data" here means the JWT.
//
func makeJwt(session c.Session) (string, error) {
	sig, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.HS256, Key: session.ClientToken},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	if err != nil {
		return "", err
	}

	encoded := c.SymmetricEncryptBase64Encode(session.ClientToken, session.ServerToken)

	claims := jwt.Claims{
		Expiry:   jwt.NewNumericDate(session.ExpiresAt),
		Audience: []string{encoded},
	}

	raw, err := jwt.Signed(sig).Claims(claims).CompactSerialize()
	if err != nil {
		return "", err
	}

	return raw, nil
}
