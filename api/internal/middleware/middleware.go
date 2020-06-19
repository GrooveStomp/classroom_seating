package middleware

import (
	"context"
	"database/sql"
	"net/http"
	"strings"
	"time"

	"github.com/Masterminds/squirrel"
	"github.com/throttled/throttled"
	"gopkg.in/square/go-jose.v2/jwt"

	c "github.com/GrooveStomp/classroom_seating/internal/common"
	log "github.com/sirupsen/logrus"
)

func Throttle(next http.Handler) http.Handler {
	store := NewGcraStore()
	quota := throttled.RateQuota{MaxRate: throttled.PerMin(20), MaxBurst: 5}

	rateLimiter, err := throttled.NewGCRARateLimiter(store, quota)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Info("Rate limit exceeded")
	}

	httpRateLimiter := throttled.HTTPRateLimiter{
		RateLimiter: rateLimiter,
		VaryBy:      &throttled.VaryBy{Path: true},
	}

	return httpRateLimiter.RateLimit(next)
}

func Log(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		t1 := time.Now()
		next.ServeHTTP(w, r)
		t2 := time.Now()
		log.WithFields(log.Fields{"method": r.Method, "url": r.URL.String(), "duration": t2.Sub(t1)}).Info("[%s] %q")
	}

	return http.HandlerFunc(fn)
}

func MakeAuthenticate(psql squirrel.StatementBuilderType, db *sql.DB) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {

			//-- Get the session info via the X-Client-Token -------------------------

			// Get the header.
			clientToken := r.Header.Get("X-Client-Token")

			// Find a session matching te header.
			query := psql.Select("id", "user_id", "server_token", "client_token", "expires_at").
				From("sessions").
				Where("client_token = ?", clientToken).
				Where("expires_at > ?", time.Now()).
				RunWith(db)

			session := c.Session{}
			err := query.Scan(&session.Id, &session.UserId, &session.ServerToken, &session.ClientToken, &session.ExpiresAt)
			if err != nil {
				log.WithFields(log.Fields{"error": err}).Info("Couldn't retrieve session")
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			// Update our session so it doesn't expire for another 7 days.
			queryUpdate := psql.Update("sessions").
				SetMap(squirrel.Eq{"updated_at": time.Now(), "expires_at": time.Now().AddDate(0, 7, 0)}).
				Where("id = ?", session.Id).
				Suffix("RETURNING id").
				RunWith(db)

			var _id int
			err = queryUpdate.Scan(&_id)
			if err != nil {
				log.WithFields(log.Fields{"error": err}).Info("Couldn't update session")
				http.Error(w, "Error", http.StatusInternalServerError)
				return
			}

			// Now we want to get information from the JWT and compare it against our
			// session data.

			// Get the JWT.
			fullHeader := r.Header.Get("Authorization")
			parts := strings.Split(fullHeader, " ")
			if parts[0] != "Bearer" {
				log.Info("Authorization type was not Bearer")
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
			}
			webToken := parts[1]

			tok, err := jwt.ParseSignedAndEncrypted(webToken)
			if err != nil {
				log.WithFields(log.Fields{"error": err}).Info("Couldn't parse jwt")
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			nested, err := tok.Decrypt(session.ClientToken)
			if err != nil {
				log.WithFields(log.Fields{"error": err}).Info("Couldn't decrypt jwt")
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			claims := jwt.Claims{}
			if err := nested.Claims(session.ClientToken, &claims); err != nil {
				log.WithFields(log.Fields{"error": err}).Info("Couldn't read jwt claims")
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			encoded := c.SymmetricEncryptBase64Encode(session.ClientToken, session.ServerToken)

			// Verify the JWT matches our session.
			if !claims.Audience.Contains(encoded) {
				log.Info("Encrypted server token doesn't match")
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			// Setup the request context so we have pervasive access to the User ID.
			ctx := context.WithValue(r.Context(), "userId", session.UserId)
			next.ServeHTTP(w, r.WithContext(ctx))
		}

		return http.HandlerFunc(fn)
	}
}
