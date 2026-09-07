package ratelimit

// Tests unitarios del token bucket zero-dep (S4, RL-1/RL-2/D1-D3).
// White-box (package ratelimit): los constructores internos newBucket/newClient
// aceptan un reloj inyectable para fijar el tiempo en las aserciones; Allow()
// y Allow(key) son la misma ruta de producción que corre en -race.

import (
	"strconv"
	"sync"
	"testing"
	"time"
)

// TestRateLimitConstantsMatchDesign: los valores numéricos son constantes
// NOMBRADAS con los valores exactos del design (D1/D2): login por cliente
// 5/min burst 5, techo global 60/min burst 60, API 120/min burst 30 e idle
// timeout de cliente de 30 minutos.
func TestRateLimitConstantsMatchDesign(t *testing.T) {
	tests := []struct {
		name string
		got  int
		want int
	}{
		{"LoginPerClientPerMinute", LoginPerClientPerMinute, 5},
		{"LoginPerClientBurst", LoginPerClientBurst, 5},
		{"LoginGlobalPerMinute", LoginGlobalPerMinute, 60},
		{"LoginGlobalBurst", LoginGlobalBurst, 60},
		{"APIPerMinute", APIPerMinute, 120},
		{"APIBurst", APIBurst, 30},
	}
	for _, tt := range tests {
		if tt.got != tt.want {
			t.Errorf("%s: se esperaba %d, se obtuvo %d", tt.name, tt.want, tt.got)
		}
	}
	if ClientIdleTimeout != 30*time.Minute {
		t.Errorf("ClientIdleTimeout: se esperaba 30m, se obtuvo %v", ClientIdleTimeout)
	}
}

// TestBucketAllowsBurstThenDeniesWithRetryAfter: un bucket 5/min (1 token
// cada 12s) concede exactamente su burst y luego deniega; el Retry-After
// inmediato es el tiempo hasta acumular ≥1 token: ceil(12s)=12s.
func TestBucketAllowsBurstThenDeniesWithRetryAfter(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0)
	b := newBucket(LoginPerClientPerMinute, LoginPerClientBurst, func() time.Time { return t0 })

	for i := 0; i < LoginPerClientBurst; i++ {
		if ok, retry := b.Allow(); !ok || retry != 0 {
			t.Fatalf("request %d dentro del burst: se esperaba ok=true retry=0, se obtuvo ok=%v retry=%v", i+1, ok, retry)
		}
	}
	ok, retry := b.Allow()
	if ok {
		t.Fatal("el sexto request debe denegarse (burst 5 agotado)")
	}
	if retry != 12*time.Second {
		t.Errorf("Retry-After inmediato: se esperaba 12s (ceil hasta ≥1 token), se obtuvo %v", retry)
	}
}

// TestBucketRefillsOverTimeAndRecovers: el refill es continuo (12s por token
// en un bucket 5/min). A +6s hay medio token (deniega con retry 6s); a +12s
// hay ≥1 token y el request pasa; el siguiente inmediato vuelve a denegar.
func TestBucketRefillsOverTimeAndRecovers(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0)
	now := t0
	b := newBucket(LoginPerClientPerMinute, LoginPerClientBurst, func() time.Time { return now })

	for i := 0; i < LoginPerClientBurst; i++ {
		b.Allow()
	}

	now = t0.Add(6 * time.Second)
	if ok, retry := b.Allow(); ok {
		t.Fatal("a +6s (medio token) el request debe denegarse")
	} else if retry != 6*time.Second {
		t.Errorf("a +6s el retry debe ser 6s (medio token restante), se obtuvo %v", retry)
	}

	now = t0.Add(12 * time.Second)
	if ok, retry := b.Allow(); !ok || retry != 0 {
		t.Errorf("a +12s debe acumularse ≥1 token y concederse, se obtuvo ok=%v retry=%v", ok, retry)
	}

	// Recién concedido: el bucket quedó en 0 tokens; el siguiente deniega.
	if ok, _ := b.Allow(); ok {
		t.Error("tras conceder el token acumulado el siguiente request debe denegarse")
	}
}

// TestBucketCapacityClampsAtBurst: un cliente idle 10 minutos acumula 50
// tokens teóricos (5/min) pero la capacidad lo recorta al burst: concede
// exactamente 5 requests rápidos y luego deniega (sin deuda acumulada).
func TestBucketCapacityClampsAtBurst(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0)
	now := t0
	b := newBucket(LoginPerClientPerMinute, LoginPerClientBurst, func() time.Time { return now })

	for i := 0; i < LoginPerClientBurst; i++ {
		b.Allow()
	}
	now = t0.Add(10 * time.Minute) // 50 tokens teóricos → clamp a 5

	for i := 0; i < LoginPerClientBurst; i++ {
		if ok, _ := b.Allow(); !ok {
			t.Fatalf("request %d tras el clamp debe concederse (burst completo), se denegó", i+1)
		}
	}
	if ok, _ := b.Allow(); ok {
		t.Error("el sexto request tras el clamp debe denegarse: la capacidad no acumula deuda")
	}
}

// TestBucketGlobalCeilingRetryAfterOneSecond: el techo global de login
// (60/min = 1 token/s) agotado deniega con Retry-After de 1s.
func TestBucketGlobalCeilingRetryAfterOneSecond(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0)
	b := newBucket(LoginGlobalPerMinute, LoginGlobalBurst, func() time.Time { return t0 })

	for i := 0; i < LoginGlobalBurst; i++ {
		if ok, _ := b.Allow(); !ok {
			t.Fatalf("request %d del techo global debe concederse, se denegó", i+1)
		}
	}
	ok, retry := b.Allow()
	if ok {
		t.Fatal("el request 61 del techo global debe denegarse")
	}
	if retry != 1*time.Second {
		t.Errorf("Retry-After del techo global: se esperaba 1s (1 token/s), se obtuvo %v", retry)
	}
}

// TestBucketAPIBurstRetryAfterOneSecond: el bucket de API (120/min = 2
// tokens/s, burst 30) agotado deniega con Retry-After de 1s (ceil(0.5s)).
func TestBucketAPIBurstRetryAfterOneSecond(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0)
	b := newBucket(APIPerMinute, APIBurst, func() time.Time { return t0 })

	for i := 0; i < APIBurst; i++ {
		if ok, _ := b.Allow(); !ok {
			t.Fatalf("request %d del burst de API debe concederse, se denegó", i+1)
		}
	}
	ok, retry := b.Allow()
	if ok {
		t.Fatal("el request 31 del burst de API debe denegarse")
	}
	if retry != 1*time.Second {
		t.Errorf("Retry-After de API: se esperaba 1s (ceil de 0.5s a 2 tokens/s), se obtuvo %v", retry)
	}
}

// TestClientLimiterSeparatesClients: los buckets son POR CLAVE (RemoteAddr):
// agotar el cliente A no afecta al cliente B.
func TestClientLimiterSeparatesClients(t *testing.T) {
	c := NewClient(LoginPerClientPerMinute, LoginPerClientBurst)

	for i := 0; i < LoginPerClientBurst; i++ {
		if ok, _ := c.Allow("203.0.113.10:1234"); !ok {
			t.Fatalf("request %d del cliente A debe concederse, se denegó", i+1)
		}
	}
	if ok, _ := c.Allow("203.0.113.10:1234"); ok {
		t.Error("el sexto request del cliente A debe denegarse (burst agotado)")
	}
	if ok, retry := c.Allow("198.51.100.77:4321"); !ok {
		t.Errorf("el cliente B (clave distinta) debe tener su propio bucket lleno: denegado con retry=%v", retry)
	}
}

// TestClientLimiterRetryAfterTwelveSeconds: ClientLimiter propaga el
// Retry-After del bucket del cliente agotado (12s para 5/min).
func TestClientLimiterRetryAfterTwelveSeconds(t *testing.T) {
	c := NewClient(LoginPerClientPerMinute, LoginPerClientBurst)

	for i := 0; i < LoginPerClientBurst; i++ {
		c.Allow("203.0.113.10:1234")
	}
	ok, retry := c.Allow("203.0.113.10:1234")
	if ok {
		t.Fatal("el sexto request debe denegarse")
	}
	if retry != 12*time.Second {
		t.Errorf("Retry-After por cliente: se esperaba 12s, se obtuvo %v", retry)
	}
}

// TestClientLimiterPrunesIdleClients: el prune lazy en Allow elimina los
// clients idle >30 min (ClientIdleTimeout) sin goroutines: tras avanzar el
// reloj, un cliente inactivo desaparece del mapa y uno activo se conserva; el
// cliente podado se recrea fresco en su siguiente request.
func TestClientLimiterPrunesIdleClients(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0)
	now := t0
	c := newClient(LoginPerClientPerMinute, LoginPerClientBurst, func() time.Time { return now })

	if ok, _ := c.Allow("idle-cliente"); !ok {
		t.Fatal("el primer request del cliente idle debe concederse")
	}
	if ok, _ := c.Allow("cliente-activo"); !ok {
		t.Fatal("el primer request del cliente activo debe concederse")
	}

	// El cliente activo sigue operando a los 10 minutos (dentro del idle window).
	now = t0.Add(10 * time.Minute)
	if ok, _ := c.Allow("cliente-activo"); !ok {
		t.Fatal("el cliente activo debe seguir operando a los 10 min")
	}

	// A los 36 minutos (26 min desde su última actividad) el sweep lazy corre:
	// idle-cliente (36 min idle) se poda; cliente-activo (26 min idle) se conserva.
	now = t0.Add(36 * time.Minute)
	active := c.clients["cliente-activo"]
	if ok, _ := c.Allow("cliente-activo"); !ok {
		t.Fatal("el cliente activo debe conservar su bucket tras el sweep")
	}
	if len(c.clients) != 1 {
		t.Fatalf("el sweep debe podar al cliente idle: se esperaba 1 cliente, hay %d", len(c.clients))
	}
	if _, pruned := c.clients["idle-cliente"]; pruned {
		t.Fatal("idle-cliente (36 min idle > 30 min) debe haber sido podado del mapa")
	}
	if c.clients["cliente-activo"] != active {
		t.Error("cliente-activo (26 min idle < 30 min) debe conservar su entrada original")
	}

	// El cliente podado se recrea con bucket fresco en su próximo request.
	if ok, _ := c.Allow("idle-cliente"); !ok {
		t.Fatal("el cliente podado debe recrearse con bucket lleno y concederse")
	}
	if len(c.clients) != 2 {
		t.Errorf("el cliente podado debe reaparecer: se esperaban 2 clients, hay %d", len(c.clients))
	}
}

// TestBucketConcurrentAllowRace: N goroutines disputando el MISMO bucket solo
// obtienen el burst (5); el resto deniega. Corre bajo -race y verifica que la
// concesión es atómica (sin dobles concesiones).
func TestBucketConcurrentAllowRace(t *testing.T) {
	b := NewBucket(LoginPerClientPerMinute, LoginPerClientBurst)

	const workers = 20
	var wg sync.WaitGroup
	var mu sync.Mutex
	allowed, denied := 0, 0

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, _ := b.Allow()
			mu.Lock()
			if ok {
				allowed++
			} else {
				denied++
			}
			mu.Unlock()
		}()
	}
	wg.Wait()

	if allowed != LoginPerClientBurst {
		t.Errorf("concesiones concurrentes: se esperaban exactamente %d ok, se obtuvieron %d (denied=%d)", LoginPerClientBurst, allowed, denied)
	}
	if denied != workers-LoginPerClientBurst {
		t.Errorf("denegaciones concurrentes: se esperaban %d, se obtuvieron %d", workers-LoginPerClientBurst, denied)
	}
}

// TestClientLimiterConcurrentDistinctKeysRace: claves concurrentes sobre el
// ClientLimiter no se pisan entre sí ni corrompen el mapa (carrera cubierta
// por -race); todas las claves frescas se conceden.
func TestClientLimiterConcurrentDistinctKeysRace(t *testing.T) {
	c := NewClient(LoginPerClientPerMinute, LoginPerClientBurst)

	const clients = 20
	var wg sync.WaitGroup
	var mu sync.Mutex
	okCount := 0

	for i := 0; i < clients; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			// Las goroutines pares usan claves propias (exercise del mapa
			// concurrente); las impares disputan la misma clave compartida
			// (exercise del bucket compartido). Ambos caminos bajo -race.
			key := "203.0.113.10:1234"
			if n%2 == 0 {
				key = "198.51.100." + strconv.Itoa(n) + ":1234"
			}
			ok, _ := c.Allow(key)
			mu.Lock()
			if ok {
				okCount++
			}
			mu.Unlock()
		}(i)
	}
	wg.Wait()

	// 10 claves propias (1 ok c/u) + la clave compartida disputada por 10
	// goroutines (burst 5 → 5 ok). Si el mapa o los buckets se corrompen, la
	// cuenta no cierra en 15.
	if okCount != 15 {
		t.Errorf("concesiones concurrentes por cliente: se esperaban 15 ok, se obtuvieron %d", okCount)
	}
}
