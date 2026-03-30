package oidc

import (
	"context"
	"sync"
	"time"
)

// JWKSCache caches the JWKS with a configurable TTL to avoid fetching it on every request.
type JWKSCache struct {
	mu        sync.RWMutex
	jwks      *JWKS
	fetchedAt time.Time
	ttl       time.Duration
	jwksURI   string
}

// NewJWKSCache creates a new JWKS cache with the given TTL.
func NewJWKSCache(jwksURI string, ttl time.Duration) *JWKSCache {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	return &JWKSCache{
		jwksURI: jwksURI,
		ttl:     ttl,
	}
}

// Get returns the cached JWKS, fetching it if the cache is expired or empty.
func (c *JWKSCache) Get(ctx context.Context) (*JWKS, error) {
	// Fast path: check if cache is still valid.
	c.mu.RLock()
	if c.jwks != nil && time.Since(c.fetchedAt) < c.ttl {
		jwks := c.jwks
		c.mu.RUnlock()
		return jwks, nil
	}
	c.mu.RUnlock()

	// Slow path: refresh the cache.
	c.mu.Lock()
	defer c.mu.Unlock()

	// Double-check after acquiring write lock.
	if c.jwks != nil && time.Since(c.fetchedAt) < c.ttl {
		return c.jwks, nil
	}

	jwks, err := FetchJWKS(ctx, c.jwksURI)
	if err != nil {
		// If we have a stale cache, return it rather than failing.
		if c.jwks != nil {
			return c.jwks, nil
		}
		return nil, err
	}

	c.jwks = jwks
	c.fetchedAt = time.Now()
	return jwks, nil
}
