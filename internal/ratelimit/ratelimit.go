// Package ratelimit implementa el rate limiting de la UI con un token bucket
// zero-dep (solo stdlib, sin golang.org/x/time/rate): single-process, sin
// sharding (D3). Cubre RL-1 (login: por cliente + techo global) y RL-2 (/api/*
// por RemoteAddr). La clave SIEMPRE es r.RemoteAddr verbatim: X-Forwarded-For
// no se confía (no-goal del cambio security-parity-mitigation).
//
// El diseño evita goroutines y ciclos de vida: el prune de clients idle es
// lazy y amortizado dentro de Allow(), y los limitadores son globales de
// proceso (se crean al primer uso del paquete).
package ratelimit

import (
	"math"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// Constantes nombradas del diseño (D1/D2): los valores numéricos de las tasas
// viven aquí, nunca inline en los call sites.
const (
	// LoginPerClientPerMinute es la tasa de POST /login por cliente (5/min:
	// 1 token cada 12s) y LoginPerClientBurst su burst (== tasa: estricto
	// 5-y-luego-refill, RL-1/D1).
	LoginPerClientPerMinute = 5
	LoginPerClientBurst     = 5

	// LoginGlobalPerMinute es el techo global de login compartido por TODOS
	// los clients (60/min, 1 token/s) y LoginGlobalBurst su burst: acota el
	// guessing distribuido sin auto-DoS de NATs/multi-dispositivo (RL-1/D1).
	LoginGlobalPerMinute = 60
	LoginGlobalBurst     = 60

	// APIPerMinute es la tasa sostenida de /api/* por RemoteAddr (120/min,
	// nunca por debajo del piso de 60/min de la spec) y APIBurst su burst de
	// ráfaga (RL-2/D2).
	APIPerMinute = 120
	APIBurst     = 30

	// ClientIdleTimeout es el tiempo de inactividad tras el cual el prune
	// lazy elimina la entrada de un cliente del ClientLimiter (D3).
	ClientIdleTimeout = 30 * time.Minute
)

// Bucket es un token bucket con refill continuo (perMinute tokens por minuto)
// y capacidad == burst. El acceso es seguro para concurrencia (mutex). La
// concesión y el refill sharen el reloj inyectable b.now para poder fijar
// el tiempo en tests (white-box); en producción b.now es time.Now.
type Bucket struct {
	mu        sync.Mutex
	perMinute float64
	capacity  float64
	tokens    float64
	last      time.Time
	now       func() time.Time
}

// NewBucket construye un bucket con el reloj real. burst es la capacidad
// máxima y la cantidad de concesiones inmediatas disponibles.
func NewBucket(perMinute float64, burst int) *Bucket {
	return newBucket(perMinute, burst, time.Now)
}

// newBucket es el constructor con reloj inyectable (tests white-box y
// ClientLimiter, que share su reloj con los buckets de cada cliente).
func newBucket(perMinute float64, burst int, now func() time.Time) *Bucket {
	return &Bucket{
		perMinute: perMinute,
		capacity:  float64(burst),
		tokens:    float64(burst),
		last:      now(),
		now:       now,
	}
}

// Allow concede un token si hay ≥1 disponible (refill aplicado hasta el
// instante actual); si no, devuelve el tiempo que falta para acumular ≥1
// token, redondeado al segundo superior (Retry-After).
func (b *Bucket) Allow() (ok bool, retryAfter time.Duration) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.allowAt(b.now())
}

// allowAt evalúa la concesión en el instante now: aplica el refill continuo
// proporcional al tiempo transcurrido desde la última evaluación y, si hay
// ≥1 token, lo consume. El retry se mide en minutos (perMinute es una tasa
// por minuto) para no acumular drift en los múltiplos exactos (p.ej. 12s →
// 1 token en un bucket 5/min).
func (b *Bucket) allowAt(now time.Time) (ok bool, retryAfter time.Duration) {
	if elapsed := now.Sub(b.last); elapsed > 0 {
		b.tokens += elapsed.Minutes() * b.perMinute
		b.last = now
		if b.tokens > b.capacity {
			b.tokens = b.capacity
		}
	}
	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	if b.perMinute <= 0 {
		// Sin refill (defensivo: los call sites usan constantes > 0): un
		// retry de una hora es el tope pragmático para no devolver infinito.
		return false, time.Hour
	}
	// Segundos enteros hasta acumular el token faltante, con una tolerancia
	// mínima que neutraliza el redondeo del punto flotante en los bordes
	// exactos (ceil(11.999999999999998) debe ser 12, no 11).
	need := 1 - b.tokens
	seconds := need / (b.perMinute / 60)
	retry := int(math.Ceil(seconds - 1e-9))
	if retry < 1 {
		retry = 1
	}
	return false, time.Duration(retry) * time.Second
}

// clientEntry agrupa el bucket de un cliente con su última actividad
// (lastSeen), que el prune lazy usa para decidir si la entrada está idle.
type clientEntry struct {
	bucket   *Bucket
	lastSeen time.Time
}

// ClientLimiter mantiene un Bucket por clave (RemoteAddr del cliente). El
// mapa crece con los clients vistos y se poda de forma lazy y amortizada
// dentro de Allow: el barrido completo corre como mucho una vez por
// ClientIdleTimeout (no por request) y sin goroutines ni ciclo de vida.
type ClientLimiter struct {
	mu        sync.Mutex
	perMinute float64
	burst     int
	clients   map[string]*clientEntry
	now       func() time.Time
	lastPrune time.Time
}

// NewClient construye un ClientLimiter con el reloj real.
func NewClient(perMinute float64, burst int) *ClientLimiter {
	return newClient(perMinute, burst, time.Now)
}

// newClient es el constructor con reloj inyectable (tests white-box). Los
// buckets de los clients creados en Allow sharen este mismo reloj.
func newClient(perMinute float64, burst int, now func() time.Time) *ClientLimiter {
	return &ClientLimiter{
		perMinute: perMinute,
		burst:     burst,
		clients:   make(map[string]*clientEntry),
		now:       now,
	}
}

// Allow concede (o no) un token al bucket de la clave, creándolo si es la
// primera vez. Antes de evaluar corre el prune lazy amortizado: elimina los
// clients idle > ClientIdleTimeout. Toda llamada cuenta como actividad de la
// clave (lastSeen se actualiza también en las denegaciones).
func (c *ClientLimiter) Allow(key string) (ok bool, retryAfter time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := c.now()
	if now.Sub(c.lastPrune) > ClientIdleTimeout {
		for k, entry := range c.clients {
			if now.Sub(entry.lastSeen) > ClientIdleTimeout {
				delete(c.clients, k)
			}
		}
		c.lastPrune = now
	}

	entry, exists := c.clients[key]
	if !exists {
		entry = &clientEntry{bucket: newBucket(c.perMinute, c.burst, c.now)}
		c.clients[key] = entry
	}
	entry.lastSeen = now
	return entry.bucket.Allow()
}

// limitadores compartidos del proceso (single-process, D3). El techo global
// de login es un Bucket único; los demás son por RemoteAddr.
var (
	loginClient = NewClient(LoginPerClientPerMinute, LoginPerClientBurst)
	loginGlobal = NewBucket(LoginGlobalPerMinute, LoginGlobalBurst)
	apiClient   = NewClient(APIPerMinute, APIBurst)
)

// tooManyRequests responde 429 con Retry-After y un cuerpo plano, sin
// Set-Cookie: el short-circuit ocurre ANTES de auth/CSRF/RequestLogger, así
// un 429 nunca fija cookie ni inunda el log de ui_request (D4).
func tooManyRequests(w http.ResponseWriter, retryAfter time.Duration) {
	w.Header().Set("Retry-After", strconv.Itoa(int(retryAfter/time.Second)))
	http.Error(w, "demasiadas peticiones, reintente más tarde", http.StatusTooManyRequests)
}

// Login envuelve el mux público de login limitando SOLO el POST (RL-1): los
// métodos seguros (GET /login) pasan sin consumir tokens, así la página de
// login nunca queda bloqueada por el límite de intentos (RL-3/D4). El orden
// es por-cliente y luego techo global.
func Login(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			next.ServeHTTP(w, r)
			return
		}
		if ok, retryAfter := loginClient.Allow(r.RemoteAddr); !ok {
			tooManyRequests(w, retryAfter)
			return
		}
		if ok, retryAfter := loginGlobal.Allow(); !ok {
			tooManyRequests(w, retryAfter)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// API limita /api/* por RemoteAddr (RL-2/D2). Se monta FUERA de
// auth.Middleware (D4): las probes sin token consumen presupuesto y el 429
// corta antes de auth/CSRF/RequestLogger. Aplica a todos los métodos.
func API(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ok, retryAfter := apiClient.Allow(r.RemoteAddr); !ok {
			tooManyRequests(w, retryAfter)
			return
		}
		next.ServeHTTP(w, r)
	})
}
