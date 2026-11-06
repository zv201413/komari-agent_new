package dnsresolver

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"time"
)

const DefaultDNS64 = "2a00:1098:2c::1"
const resolverAttemptTimeout = 5 * time.Second
const lookupAttemptTimeout = 2 * time.Second

var FallbackDNSServer string

func SetFallbackDNSServer(server string) {
	if server == "" {
		FallbackDNSServer = ""
		return
	}
	FallbackDNSServer = normalizeDNSServer(server)
}

type resolverSource struct {
	name     string
	resolver *net.Resolver
}

func serverResolver(server string) *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			// Respect TCP retries for truncated UDP DNS responses.
			return (&net.Dialer{}).DialContext(ctx, network, server)
		},
	}
}

func resolverSources() []resolverSource {
	custom, fallback := CustomDNSServer, FallbackDNSServer
	// Older generated commands used --custom-dns for the public DNS64 service.
	// Keep those installations working without letting this optional path block IPv4.
	if custom == normalizeDNSServer(DefaultDNS64) {
		if fallback == "" {
			fallback = custom
		}
		custom = ""
	}
	sources := []resolverSource{}
	if custom != "" {
		sources = append(sources, resolverSource{"custom DNS", serverResolver(custom)})
	}
	sources = append(sources, resolverSource{"system DNS", net.DefaultResolver})
	if fallback != "" && fallback != custom {
		sources = append(sources, resolverSource{"fallback DNS", serverResolver(fallback)})
	}
	return sources
}

func newDialContext(timeout time.Duration, preference string, sources []resolverSource, attemptTimeout time.Duration) func(context.Context, string, string) (net.Conn, error) {
	return func(parent context.Context, network, address string) (net.Conn, error) {
		ctx, cancel := context.WithTimeout(parent, timeout)
		defer cancel()
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		if net.ParseIP(host) != nil {
			return (&net.Dialer{KeepAlive: 30 * time.Second}).DialContext(ctx, network, address)
		}
		var failures []error
		for index, source := range sources {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			budget := attemptTimeout
			if len(sources) == 1 {
				budget = timeout
			}
			conn, err := dialSource(ctx, network, host, port, preference, source, budget, len(sources) > 1)
			if err == nil {
				return conn, nil
			}
			failures = append(failures, fmt.Errorf("%s: %w", source.name, err))
			if index+1 < len(sources) && ctx.Err() == nil {
				log.Printf("%s lookup/connection failed; trying %s: %v", source.name, sources[index+1].name, err)
			}
		}
		return nil, fmt.Errorf("all DNS/connection paths failed: %w", errors.Join(failures...))
	}
}

func dialSource(ctx context.Context, network, host, port, preference string, source resolverSource, attemptTimeout time.Duration, boundedFallback bool) (net.Conn, error) {
	attemptCtx, cancel := context.WithTimeout(ctx, attemptTimeout)
	defer cancel()
	lookupBudget, addressBudget := attemptTimeout, attemptTimeout
	if boundedFallback {
		lookupBudget, addressBudget = lookupAttemptTimeout, 2*time.Second
	}
	lookupCtx, lookupCancel := context.WithTimeout(attemptCtx, lookupBudget)
	ips, err := source.resolver.LookupHost(lookupCtx, host)
	lookupCancel()
	if err != nil {
		return nil, err
	}
	sortIPsByPreference(ips, preference)
	var failures []error
	for _, ip := range ips {
		parsed := net.ParseIP(ip)
		if parsed == nil || ((network == "tcp4" || network == "udp4") && parsed.To4() == nil) || ((network == "tcp6" || network == "udp6") && parsed.To4() != nil) {
			continue
		}
		// A dead first address must leave time for other addresses and DNS64.
		conn, err := (&net.Dialer{Timeout: addressBudget, KeepAlive: 30 * time.Second}).DialContext(attemptCtx, network, net.JoinHostPort(ip, port))
		if err == nil {
			return conn, nil
		}
		failures = append(failures, err)
		if attemptCtx.Err() != nil {
			break
		}
	}
	if len(failures) == 0 {
		return nil, fmt.Errorf("no resolved address for %s", network)
	}
	return nil, errors.Join(failures...)
}
