package middleware

import (
	"net/http"
	"time"

	// TODO: "github.com/justinas/nosurf"

	log "github.com/sirupsen/logrus"

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
