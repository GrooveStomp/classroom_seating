package middleware

import (
	"context"
	"database/sql"
	"net/http"
	"time"

	// TODO: "github.com/justinas/nosurf"

	log "github.com/sirupsen/logrus"

	"github.com/Masterminds/squirrel"
	"github.com/throttled/throttled"
)

func Throttle(next http.Handler) http.Handler {
	store := NewGcraStore()
	quota := throttled.RateQuota{MaxRate: throttled.PerMin(20), MaxBurst: 5}

	rateLimiter, err := throttled.NewGCRARateLimiter(store, quota)
	if err != nil {
		log.Fatal(err)
	}

	httpRateLimiter := throttled.HTTPRateLimiter{
		RateLimiter: rateLimiter,
		VaryBy:      &throttled.VaryBy{Path: true},
	}

	return httpRateLimiter.RateLimit(next)
}

func Cors(next http.Handler) http.Handler {
	// TODO: return nosurf.NewPure(next)
	return next
}

func Log(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		t1 := time.Now()
		next.ServeHTTP(w, r)
		t2 := time.Now()
		log.Printf("[%s] %q %v\n", r.Method, r.URL.String(), t2.Sub(t1))
	}

	return http.HandlerFunc(fn)
}

func MakeAuthenticate(psql squirrel.StatementBuilderType, db *sql.DB) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			token := r.Header.Get("X-Auth-Token")

			fifteenMinutesAgo := time.Now().Add(-time.Minute * 15)

			var userId string
			query := psql.Select("user_id").
				From("authentications").
				Where("token = ?", token).
				Where("deleted_at IS NULL").
				Where("updated_at > ?", fifteenMinutesAgo).
				RunWith(db)

			err := query.Scan(&userId)
			if err != nil {
				log.Print(err)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			} else {
				// We have an auth token that is still valid, let's use that.
				queryUpdate := psql.Update("authentications").
					SetMap(squirrel.Eq{"updated_at": time.Now()}).
					Where("token = ?", token).
					Where("deleted_at IS NULL").
					Suffix("RETURNING id").
					RunWith(db)

				var _id int
				err = queryUpdate.Scan(&_id)
				if err != nil {
					log.Printf("Couldn't update existing auth token: %#+v\n", err)
					http.Error(w, "Error", http.StatusInternalServerError)
					return
				}

				ctx := context.WithValue(r.Context(), "userId", userId)
				next.ServeHTTP(w, r.WithContext(ctx))
			}
		}

		return http.HandlerFunc(fn)
	}
}
