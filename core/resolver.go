package core

import (
	"errors"
	"math/rand"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/sync/singleflight"
)

// DnsResolver represents a dns resolver
type DnsResolver struct {
	Servers    []string
	RetryTimes int
	r          *rand.Rand

	mu    sync.RWMutex
	cache map[string]*cacheEntry

	// OnCacheMiss is executed if the host or address is not included in
	// the cache and the default lookup is executed.
	OnCacheMiss func()
}

type cacheEntry struct {
	rrs  []net.IP
	err  error
	used bool
}

// New initializes DnsResolver.
func NewDnsResolver(servers []string) *DnsResolver {
	for i := range servers {
		servers[i] = net.JoinHostPort(servers[i], "53")
	}

	return &DnsResolver{Servers: servers, RetryTimes: len(servers) * 2, r: rand.New(rand.NewSource(time.Now().UnixNano())), cache: make(map[string]*cacheEntry)}
}

// NewDnsResolverFromConf initializes DnsResolver from resolv.conf like file.
func NewDnsResolverFromConf(path string) (*DnsResolver, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return &DnsResolver{}, errors.New("no such file or directory: " + path)
	}
	config, err := dns.ClientConfigFromFile(path)
	var servers []string
	for _, ipAddress := range config.Servers {
		servers = append(servers, net.JoinHostPort(ipAddress, "53"))
	}
	return NewDnsResolver(servers), err
}

// LookupHost returns IP addresses of provide host.
// In case of timeout retries query RetryTimes times.
func (r *DnsResolver) LookupHost(host string) ([]net.IP, error) {
	return r.lookup("h" + host)
}

// Refresh refreshes cached entries which has been used at least once since the
// last Refresh. If clearUnused is true, entries which hasn't be used since the
// last Refresh are removed from the cache.
func (r *DnsResolver) Refresh(clearUnused bool) {
	r.mu.RLock()
	update := make([]string, 0, len(r.cache))
	del := make([]string, 0, len(r.cache))
	for key, entry := range r.cache {
		if entry.used {
			update = append(update, key)
		} else if clearUnused {
			del = append(del, key)
		}
	}
	r.mu.RUnlock()

	if len(del) > 0 {
		r.mu.Lock()
		for _, key := range del {
			delete(r.cache, key)
		}
		r.mu.Unlock()
	}

	for _, key := range update {
		r.update(key, false)
	}
}

func (r *DnsResolver) lookupHost(host string, triesLeft int) ([]net.IP, error) {
	m1 := new(dns.Msg)
	m1.Id = dns.Id()
	m1.RecursionDesired = true
	m1.Question = make([]dns.Question, 1)
	m1.Question[0] = dns.Question{Name: dns.Fqdn(host), Qtype: dns.TypeA, Qclass: dns.ClassINET}
	in, err := dns.Exchange(m1, r.Servers[r.r.Intn(len(r.Servers))])

	var result []net.IP

	if err != nil {
		if strings.HasSuffix(err.Error(), "i/o timeout") && triesLeft > 0 {
			triesLeft--
			return r.lookupHost(host, triesLeft)
		}
		return result, err
	}

	if in != nil && in.Rcode != dns.RcodeSuccess {
		return result, errors.New(dns.RcodeToString[in.Rcode])
	}

	for _, record := range in.Answer {
		if t, ok := record.(*dns.A); ok {
			result = append(result, t.A)
		}
	}
	return result, err
}

// lookupGroup merges lookup calls together for lookups for the same host. The
// lookupGroup key is is the LookupIPAddr.host argument.
var lookupGroup singleflight.Group

func (r *DnsResolver) lookup(key string) (rrs []net.IP, err error) {
	var found bool
	rrs, err, found = r.load(key)
	if !found {
		if r.OnCacheMiss != nil {
			r.OnCacheMiss()
		}
		rrs, err = r.update(key, true)
	}
	return
}

func (r *DnsResolver) update(key string, used bool) (rrs []net.IP, err error) {
	c := lookupGroup.DoChan(key, r.lookupFunc(key))
	select {
	case res := <-c:
		if res.Shared {
			// We had concurrent lookups, check if the cache is already updated
			// by a friend.
			var found bool
			rrs, err, found = r.load(key)
			if found {
				return
			}
		}
		err = res.Err
		if err == nil {
			rrs, _ = res.Val.([]net.IP)
		}
		r.mu.Lock()
		r.storeLocked(key, rrs, used, err)
		r.mu.Unlock()
	}
	return
}

// lookupFunc returns lookup function for key. The type of the key is stored as
// the first char and the lookup subject is the rest of the key.
func (r *DnsResolver) lookupFunc(key string) func() (interface{}, error) {
	if len(key) == 0 {
		panic("lookupFunc with empty key")
	}

	switch key[0] {
	case 'h':
		return func() (interface{}, error) {
			return r.lookupHost(key[1:], r.RetryTimes)
		}
	default:
		panic("lookupFunc invalid key type: " + key)
	}
}

func (r *DnsResolver) load(key string) (rrs []net.IP, err error, found bool) {
	r.mu.RLock()
	var entry *cacheEntry
	entry, found = r.cache[key]
	if !found {
		r.mu.RUnlock()
		return
	}
	rrs = entry.rrs
	err = entry.err
	used := entry.used
	r.mu.RUnlock()
	if !used {
		r.mu.Lock()
		entry.used = true
		r.mu.Unlock()
	}
	return rrs, err, true
}

func (r *DnsResolver) storeLocked(key string, rrs []net.IP, used bool, err error) {
	if entry, found := r.cache[key]; found {
		// Update existing entry in place
		entry.rrs = rrs
		entry.err = err
		entry.used = used
		return
	}
	r.cache[key] = &cacheEntry{
		rrs:  rrs,
		err:  err,
		used: used,
	}
}
