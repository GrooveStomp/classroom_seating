package middleware

import (
	"time"
)

type GcraStore struct {
	mem map[string]int64
}

func NewGcraStore() *GcraStore {
	store := &GcraStore{}
	store.mem = make(map[string]int64)
	return store
}

func (store *GcraStore) GetWithTime(key string) (int64, time.Time, error) {
	v, ok := store.mem[key]
	if !ok {
		return -1, time.Now(), nil
	}

	return v, time.Now(), nil
}

func (store *GcraStore) SetIfNotExistsWithTTL(key string, value int64, ttl time.Duration) (bool, error) {
	_, ok := store.mem[key]
	if !ok {
		store.mem[key] = value
		return true, nil
	}

	return false, nil
}

func (store *GcraStore) CompareAndSwapWithTTL(key string, old, new int64, ttl time.Duration) (bool, error) {
	v, ok := store.mem[key]
	if !ok {
		return false, nil
	}

	if v == old {
		store.mem[key] = new
		return true, nil
	} else {
		return false, nil
	}
}
