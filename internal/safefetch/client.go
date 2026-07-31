package safefetch

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	defaultTimeout          = 30 * time.Second
	defaultMaxResponseBytes = int64(10 << 20)
	maxRedirects            = 10
)

var (
	ErrProhibitedAddress = errors.New("destination address is not public")
	ErrResponseTooLarge  = errors.New("response body exceeds size limit")
)

type resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

type dialContextFunc func(ctx context.Context, network, address string) (net.Conn, error)

type clientOptions struct {
	timeout          time.Duration
	maxResponseBytes int64
	allowLoopback    bool
	sameOrigin       *url.URL
	resolver         resolver
	dialContext      dialContextFunc
}

// NewClient returns an HTTP client for URLs controlled by users. It does not
// honor proxy environment variables and validates DNS results both before the
// request and immediately before dialing the selected IP address.
func NewClient(timeout time.Duration, maxResponseBytes int64) *http.Client {
	return newClient(clientOptions{timeout: timeout, maxResponseBytes: maxResponseBytes})
}

// NewSameOriginClient is used by the legacy-panel migration flow, where every
// redirect must remain on the authenticated source origin. Loopback can only be
// enabled by that flow's explicit local-migration option.
func NewSameOriginClient(timeout time.Duration, maxResponseBytes int64, origin *url.URL, allowLoopback bool) *http.Client {
	return newClient(clientOptions{
		timeout:          timeout,
		maxResponseBytes: maxResponseBytes,
		sameOrigin:       origin,
		allowLoopback:    allowLoopback,
	})
}

func newClient(options clientOptions) *http.Client {
	if options.timeout <= 0 {
		options.timeout = defaultTimeout
	}
	if options.maxResponseBytes <= 0 {
		options.maxResponseBytes = defaultMaxResponseBytes
	}
	if options.resolver == nil {
		options.resolver = net.DefaultResolver
	}
	if options.dialContext == nil {
		dialer := &net.Dialer{Timeout: minDuration(options.timeout, 10*time.Second), KeepAlive: 30 * time.Second}
		options.dialContext = dialer.DialContext
	}

	safeDial := func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, fmt.Errorf("invalid destination address: %w", err)
		}
		addresses, err := resolvePublicAddresses(ctx, options.resolver, host, options.allowLoopback)
		if err != nil {
			return nil, err
		}

		var dialErrors []error
		for _, address := range addresses {
			// Dial the already-validated literal address so the system resolver
			// cannot perform a second, attacker-controlled lookup.
			connection, dialErr := options.dialContext(ctx, network, net.JoinHostPort(address.String(), port))
			if dialErr == nil {
				return connection, nil
			}
			dialErrors = append(dialErrors, dialErr)
		}
		return nil, fmt.Errorf("dial public destination: %w", errors.Join(dialErrors...))
	}

	responseHeaderTimeout := minDuration(options.timeout, 30*time.Second)
	transport := &http.Transport{
		Proxy:                  nil,
		DialContext:            safeDial,
		ForceAttemptHTTP2:      true,
		MaxIdleConns:           32,
		MaxIdleConnsPerHost:    4,
		IdleConnTimeout:        90 * time.Second,
		TLSHandshakeTimeout:    minDuration(options.timeout, 10*time.Second),
		ResponseHeaderTimeout:  responseHeaderTimeout,
		ExpectContinueTimeout:  time.Second,
		MaxResponseHeaderBytes: 1 << 20,
	}
	roundTripper := &validatingRoundTripper{
		base:             transport,
		resolver:         options.resolver,
		allowLoopback:    options.allowLoopback,
		maxResponseBytes: options.maxResponseBytes,
	}

	return &http.Client{
		Timeout:   options.timeout,
		Transport: roundTripper,
		CheckRedirect: func(request *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return errors.New("too many redirects")
			}
			if options.sameOrigin != nil && !sameOrigin(options.sameOrigin, request.URL) {
				return errors.New("redirect destination is not on the original host")
			}
			return validateRequestURL(request.Context(), request.URL, options.resolver, options.allowLoopback)
		},
	}
}

type validatingRoundTripper struct {
	base             http.RoundTripper
	resolver         resolver
	allowLoopback    bool
	maxResponseBytes int64
}

func (t *validatingRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	if err := validateRequestURL(request.Context(), request.URL, t.resolver, t.allowLoopback); err != nil {
		return nil, err
	}
	response, err := t.base.RoundTrip(request)
	if err != nil {
		return nil, err
	}
	if response.ContentLength > t.maxResponseBytes {
		_ = response.Body.Close()
		return nil, fmt.Errorf("%w: limit=%d content-length=%d", ErrResponseTooLarge, t.maxResponseBytes, response.ContentLength)
	}
	response.Body = &limitedReadCloser{ReadCloser: response.Body, remaining: t.maxResponseBytes}
	return response, nil
}

type limitedReadCloser struct {
	io.ReadCloser
	remaining int64
	exhausted bool
}

func (r *limitedReadCloser) Read(buffer []byte) (int, error) {
	if r.remaining > 0 {
		if int64(len(buffer)) > r.remaining {
			buffer = buffer[:r.remaining]
		}
		n, err := r.ReadCloser.Read(buffer)
		r.remaining -= int64(n)
		return n, err
	}
	if r.exhausted {
		return 0, ErrResponseTooLarge
	}
	r.exhausted = true
	var probe [1]byte
	n, err := r.ReadCloser.Read(probe[:])
	if n > 0 {
		return 0, ErrResponseTooLarge
	}
	if err == nil {
		return 0, io.EOF
	}
	return 0, err
}

func validateRequestURL(ctx context.Context, target *url.URL, resolver resolver, allowLoopback bool) error {
	if target == nil {
		return errors.New("destination URL is required")
	}
	if target.User != nil {
		return errors.New("destination URL must not include user information")
	}
	switch strings.ToLower(target.Scheme) {
	case "http", "https":
	default:
		return errors.New("destination URL must use http or https")
	}
	if strings.TrimSpace(target.Hostname()) == "" {
		return errors.New("destination URL host is required")
	}
	if target.Port() != "" {
		port, err := strconv.ParseUint(target.Port(), 10, 16)
		if err != nil || port == 0 {
			return errors.New("destination URL port is invalid")
		}
	}
	_, err := resolvePublicAddresses(ctx, resolver, target.Hostname(), allowLoopback)
	return err
}

func resolvePublicAddresses(ctx context.Context, resolver resolver, host string, allowLoopback bool) ([]netip.Addr, error) {
	host = strings.TrimSpace(strings.TrimSuffix(host, "."))
	if host == "" {
		return nil, errors.New("destination host is required")
	}

	var addresses []netip.Addr
	if parsed, err := netip.ParseAddr(host); err == nil {
		addresses = []netip.Addr{parsed}
	} else {
		resolved, err := resolver.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return nil, fmt.Errorf("resolve destination host: %w", err)
		}
		addresses = resolved
	}
	if len(addresses) == 0 {
		return nil, errors.New("destination host did not resolve to an IP address")
	}

	validated := make([]netip.Addr, 0, len(addresses))
	for _, address := range addresses {
		address = address.Unmap()
		if !isAllowedAddress(address, allowLoopback) {
			return nil, fmt.Errorf("%w: %s", ErrProhibitedAddress, address)
		}
		validated = append(validated, address)
	}
	return validated, nil
}

var prohibitedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::/128"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("3fff::/20"),
	netip.MustParsePrefix("5f00::/16"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("fec0::/10"),
	netip.MustParsePrefix("ff00::/8"),
}

func isAllowedAddress(address netip.Addr, allowLoopback bool) bool {
	if !address.IsValid() {
		return false
	}
	address = address.Unmap()
	if allowLoopback && address.IsLoopback() {
		return true
	}
	if !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() {
		return false
	}
	for _, prefix := range prohibitedPrefixes {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}

func sameOrigin(a, b *url.URL) bool {
	if a == nil || b == nil || !strings.EqualFold(a.Scheme, b.Scheme) || !strings.EqualFold(a.Hostname(), b.Hostname()) {
		return false
	}
	return effectivePort(a) == effectivePort(b)
}

func effectivePort(target *url.URL) string {
	if target.Port() != "" {
		return target.Port()
	}
	if strings.EqualFold(target.Scheme, "https") {
		return "443"
	}
	return "80"
}

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}
