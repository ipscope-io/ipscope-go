package ipscope

import (
	"container/list"
	"context"
	"sync"
	"time"
)

const (
	// DefaultCacheMaxEntries caps the default in-memory LRU cache to 512 entries (< 400 KB RAM).
	DefaultCacheMaxEntries = 512
	// DefaultCacheTTL is the default time-to-live for cached IP and prefix responses.
	DefaultCacheTTL = 60 * time.Second
)

type cacheEntry[V any] struct {
	key       string
	value     V
	expiresAt time.Time
}

type inFlightCall[V any] struct {
	done chan struct{}
	val  V
	err  error
}

// lruTTLCache is a concurrency-safe O(1) Least-Recently-Used cache with TTL expiration
// and singleflight request coalescing.
type lruTTLCache[V any] struct {
	mu            sync.Mutex
	enabled       bool
	maxEntries    int
	ttl           time.Duration
	ll            *list.List
	items         map[string]*list.Element
	inFlight      map[string]*inFlightCall[V]
	hits          uint64
	misses        uint64
	coalescedHits uint64
}

func newLRUTTLCache[V any](opts CacheOptions) *lruTTLCache[V] {
	maxEntries := opts.MaxEntries
	if maxEntries <= 0 {
		maxEntries = DefaultCacheMaxEntries
	}
	ttl := opts.TTL
	if ttl <= 0 {
		ttl = DefaultCacheTTL
	}
	return &lruTTLCache[V]{
		enabled:    opts.Enabled,
		maxEntries: maxEntries,
		ttl:        ttl,
		ll:         list.New(),
		items:      make(map[string]*list.Element),
		inFlight:   make(map[string]*inFlightCall[V]),
	}
}

func (c *lruTTLCache[V]) Get(key string) (V, bool) {
	var zero V
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.enabled {
		c.misses++
		return zero, false
	}

	elem, ok := c.items[key]
	if !ok {
		c.misses++
		return zero, false
	}

	entry := elem.Value.(*cacheEntry[V])
	if !time.Now().Before(entry.expiresAt) {
		c.removeElementLocked(elem)
		c.misses++
		return zero, false
	}

	c.ll.MoveToBack(elem)
	c.hits++
	return entry.value, true
}

func (c *lruTTLCache[V]) Set(key string, value V) {
	if !c.enabled {
		return
	}
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()

	if elem, ok := c.items[key]; ok {
		c.ll.MoveToBack(elem)
		entry := elem.Value.(*cacheEntry[V])
		entry.value = value
		entry.expiresAt = now.Add(c.ttl)
		return
	}

	// Evict expired or oldest LRU entries before inserting
	for c.ll.Len() >= c.maxEntries {
		front := c.ll.Front()
		if front == nil {
			break
		}
		c.removeElementLocked(front)
	}

	entry := &cacheEntry[V]{
		key:       key,
		value:     value,
		expiresAt: now.Add(c.ttl),
	}
	elem := c.ll.PushBack(entry)
	c.items[key] = elem
}

func (c *lruTTLCache[V]) GetOrCompute(
	ctx context.Context,
	key string,
	bypassCache bool,
	producer func(ctx context.Context) (V, error),
) (V, bool, error) {
	var zero V
	if !bypassCache {
		if val, ok := c.Get(key); ok {
			return val, true, nil
		}

		c.mu.Lock()
		if call, exists := c.inFlight[key]; exists {
			c.coalescedHits++
			c.mu.Unlock()

			select {
			case <-call.done:
				if call.err != nil {
					return zero, false, call.err
				}
				return call.val, true, nil
			case <-ctx.Done():
				return zero, false, &TimeoutError{
					Path:  key,
					Cause: ctx.Err(),
				}
			}
		}

		call := &inFlightCall[V]{
			done: make(chan struct{}),
		}
		c.inFlight[key] = call
		c.mu.Unlock()

		defer func() {
			c.mu.Lock()
			delete(c.inFlight, key)
			c.mu.Unlock()
			close(call.done)
		}()

		val, err := producer(ctx)
		call.val = val
		call.err = err
		if err == nil {
			c.Set(key, val)
		}
		return val, false, err
	}

	val, err := producer(ctx)
	return val, false, err
}

func (c *lruTTLCache[V]) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ll.Init()
	clear(c.items)
	clear(c.inFlight)
	c.hits = 0
	c.misses = 0
	c.coalescedHits = 0
}

func (c *lruTTLCache[V]) Stats() CacheStats {
	c.mu.Lock()
	defer c.mu.Unlock()
	return CacheStats{
		Enabled:               c.enabled,
		Size:                  c.ll.Len(),
		MaxEntries:            c.maxEntries,
		TTL:                   c.ttl,
		Hits:                  c.hits,
		Misses:                c.misses,
		CoalescedInFlightHits: c.coalescedHits,
	}
}

func (c *lruTTLCache[V]) removeElementLocked(elem *list.Element) {
	c.ll.Remove(elem)
	entry := elem.Value.(*cacheEntry[V])
	delete(c.items, entry.key)
}
