package safefetch

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type staticResolver map[string][]netip.Addr

func (r staticResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	addresses, ok := r[host]
	if !ok {
		return nil, errors.New("host not found")
	}
	return append([]netip.Addr(nil), addresses...), nil
}

type sequenceResolver struct {
	mu        sync.Mutex
	addresses []netip.Addr
	calls     int
}

func (r *sequenceResolver) LookupNetIP(_ context.Context, _, _ string) ([]netip.Addr, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	index := r.calls
	if index >= len(r.addresses) {
		index = len(r.addresses) - 1
	}
	r.calls++
	return []netip.Addr{r.addresses[index]}, nil
}

func TestRejectsPrivateAndReservedIPv4AndIPv6(t *testing.T) {
	blocked := []string{
		"127.0.0.1", "10.0.0.1", "100.64.0.1", "169.254.169.254",
		"192.168.1.1", "198.18.0.1", "203.0.113.5",
		"::1", "fc00::1", "fe80::1", "64:ff9b::a00:1", "64:ff9b:1::1",
		"2001::1", "2001:db8::1", "2002:a00:1::1", "3fff::1", "5f00::1",
		"::ffff:127.0.0.1",
	}
	for _, address := range blocked {
		t.Run(address, func(t *testing.T) {
			var dialed atomic.Bool
			client := newClient(clientOptions{
				resolver: staticResolver{},
				dialContext: func(context.Context, string, string) (net.Conn, error) {
					dialed.Store(true)
					return nil, errors.New("unexpected dial")
				},
			})
			request, err := http.NewRequest(http.MethodGet, "http://["+address+"]/", nil)
			if strings.Contains(address, ".") && !strings.Contains(address, ":") {
				request, err = http.NewRequest(http.MethodGet, "http://"+address+"/", nil)
			}
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.Do(request)
			if !errors.Is(err, ErrProhibitedAddress) {
				t.Fatalf("address %s error=%v, want ErrProhibitedAddress", address, err)
			}
			if dialed.Load() {
				t.Fatalf("address %s reached the dialer", address)
			}
		})
	}
}

func TestRejectsPrivateRedirectBeforeFollowingIt(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/start" {
			t.Fatalf("unexpected path reached: %s", r.URL.Path)
		}
		http.Redirect(w, r, "http://private.test/metadata", http.StatusFound)
	}))
	defer server.Close()

	var dialCount atomic.Int32
	client := newClient(clientOptions{
		resolver: staticResolver{
			"public.test":  {netip.MustParseAddr("8.8.8.8")},
			"private.test": {netip.MustParseAddr("127.0.0.1")},
		},
		dialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			dialCount.Add(1)
			return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
		},
	})
	_, err := client.Get("http://public.test/start")
	if !errors.Is(err, ErrProhibitedAddress) {
		t.Fatalf("redirect error=%v, want ErrProhibitedAddress", err)
	}
	if got := dialCount.Load(); got != 1 {
		t.Fatalf("dial count=%d, want only the initial public request", got)
	}
}

func TestDNSRebindingIsRejectedAtDialTime(t *testing.T) {
	resolver := &sequenceResolver{addresses: []netip.Addr{
		netip.MustParseAddr("8.8.8.8"),
		netip.MustParseAddr("127.0.0.1"),
	}}
	var dialed atomic.Bool
	client := newClient(clientOptions{
		resolver: resolver,
		dialContext: func(context.Context, string, string) (net.Conn, error) {
			dialed.Store(true)
			return nil, errors.New("unexpected dial")
		},
	})
	_, err := client.Get("http://rebind.test/")
	if !errors.Is(err, ErrProhibitedAddress) {
		t.Fatalf("rebind error=%v, want ErrProhibitedAddress", err)
	}
	if dialed.Load() {
		t.Fatal("dialer was called after DNS changed to a private address")
	}
	if resolver.calls < 2 {
		t.Fatalf("resolver calls=%d, want validation and dial-time lookup", resolver.calls)
	}
}

func TestResponseBodyLimitAndTimeout(t *testing.T) {
	t.Run("body limit", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Length", "")
			if flusher, ok := w.(http.Flusher); ok {
				_, _ = w.Write([]byte("1234"))
				flusher.Flush()
			}
			_, _ = w.Write([]byte("5678"))
		}))
		defer server.Close()
		client := mappedTestClient(server, 5, time.Second)
		response, err := client.Get("http://public.test/data")
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		_, err = io.ReadAll(response.Body)
		if !errors.Is(err, ErrResponseTooLarge) {
			t.Fatalf("read error=%v, want ErrResponseTooLarge", err)
		}
	})

	t.Run("timeout", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			time.Sleep(150 * time.Millisecond)
			_, _ = w.Write([]byte("late"))
		}))
		defer server.Close()
		client := mappedTestClient(server, 1024, 25*time.Millisecond)
		_, err := client.Get("http://public.test/slow")
		if err == nil {
			t.Fatal("slow response was not timed out")
		}
	})
}

func mappedTestClient(server *httptest.Server, limit int64, timeout time.Duration) *http.Client {
	return newClient(clientOptions{
		timeout:          timeout,
		maxResponseBytes: limit,
		resolver: staticResolver{
			"public.test": {netip.MustParseAddr("8.8.8.8")},
		},
		dialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
		},
	})
}
