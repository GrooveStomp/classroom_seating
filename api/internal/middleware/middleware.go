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
			clientToken := r.Header.Get("X-Client-Token")

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

			// jwt will be in 'Bearer' header.
			fullHeader := r.Header.Get("Authorization")
			parts := strings.Split(fullHeader, " ")
			if parts[0] != "Bearer" {
				log.Info("Authorization type was not Bearer")
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
			}
			webToken := parts[1]

			// We have an auth token that is still valid, let's use that.
			queryUpdate := psql.Update("sessions").
				SetMap(squirrel.Eq{"updated_at": time.Now(), "expires_at": time.Now().AddDate(0, 1, 0)}).
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

			if !claims.Audience.Contains(encoded) {
				log.Info("Encrypted server token doesn't match")
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			ctx := context.WithValue(r.Context(), "userId", session.UserId)
			next.ServeHTTP(w, r.WithContext(ctx))
		}

		return http.HandlerFunc(fn)
	}
}
