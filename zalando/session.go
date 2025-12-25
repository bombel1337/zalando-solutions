package zalando

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"

	eh "github.com/enetx/http" // IMPORTANT: enetx http, not net/http
	"github.com/enetx/surf"
)

// cookies.txt structure:
//
// {
//   "email:pass": {
//     "domain.tld": {
//       "cookieName": "cookieValue"
//     }
//   }
// }
type CookieStore map[string]map[string]map[string]string

var (
	cookiesFilePath = "cookies.txt"
	fileMu          sync.Mutex
)

func (z *zalaTask) checkIfSessionExists(domain string, filterKeys []string) error {
	sessionKey := z.Data.ZalandoEmail + ":" + z.Data.ZalandoPassword

	if len(filterKeys) == 0 {
		filterKeys = []string{"zsso", "zsso-p"}
	}

	if err := checkSessionExists(sessionKey, domain, filterKeys); err != nil {
		return fmt.Errorf("not found")
	}
	return nil
}
func checkSessionExists(sessionKey, domain string, filterKeys []string) error {
	if sessionKey == "" {
		return fmt.Errorf("not found")
	}
	if domain == "" {
		return fmt.Errorf("not found")
	}
	if len(filterKeys) == 0 {
		// Default to your typical Zalando session cookies
		filterKeys = []string{"zsso", "zsso-p"}
	}

	fileMu.Lock()
	defer fileMu.Unlock()

	store, err := readStoreLocked()
	if err != nil {
		return err
	}

	byDomain, ok := store[sessionKey]
	if !ok {
		return fmt.Errorf("not found")
	}
	kv, ok := byDomain[domain]
	if !ok {
		return fmt.Errorf("not found")
	}

	for _, k := range filterKeys {
		v, ok := kv[k]
		if !ok || strings.TrimSpace(v) == "" {
			return fmt.Errorf("not found")
		}
	}

	return nil
}
func ensureCookiesFile() error {
	if _, err := os.Stat(cookiesFilePath); err == nil {
		return nil
	}
	return os.WriteFile(cookiesFilePath, []byte("{}"), 0644)
}

func readStoreLocked() (CookieStore, error) {
	if err := ensureCookiesFile(); err != nil {
		return nil, err
	}

	b, err := os.ReadFile(cookiesFilePath)
	if err != nil {
		return nil, err
	}

	if len(b) == 0 {
		return CookieStore{}, nil
	}

	var store CookieStore
	if err := json.Unmarshal(b, &store); err != nil {
		return nil, err
	}
	if store == nil {
		store = CookieStore{}
	}
	return store, nil
}

func writeStoreLocked(store CookieStore) error {
	b, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(cookiesFilePath, b, 0644)
}

func normalizeBaseURL(domain string) (*url.URL, error) {
	host := strings.TrimLeft(domain, ".")
	return url.Parse("https://" + host + "/")
}

func allowSet(filterKeys []string) map[string]struct{} {
	if len(filterKeys) == 0 {
		return nil
	}
	set := make(map[string]struct{}, len(filterKeys))
	for _, k := range filterKeys {
		set[k] = struct{}{}
	}
	return set
}

// LoadCookiesIntoClientKV reads cookies.txt and injects KV-only cookies into the surf client's cookie store.
func loadCookiesIntoClient(client *surf.Client, sessionKey, domain string, filterKeys []string) error {
	if client == nil {
		return fmt.Errorf("client is nil")
	}

	std := client.GetClient() // this is *github.com/enetx/http.Client
	if std == nil || std.Jar == nil {
		return fmt.Errorf("client has no cookie jar; ensure you used Builder().Session()")
	}

	fileMu.Lock()
	defer fileMu.Unlock()

	store, err := readStoreLocked()
	if err != nil {
		return fmt.Errorf("read cookies store: %w", err)
	}

	byDomain, ok := store[sessionKey]
	if !ok {
		return fmt.Errorf("session key %q not found", sessionKey)
	}
	kv, ok := byDomain[domain]
	if !ok {
		return fmt.Errorf("domain %q not found for session key %q", domain, sessionKey)
	}

	u, err := normalizeBaseURL(domain)
	if err != nil {
		return fmt.Errorf("invalid domain %q: %w", domain, err)
	}

	allow := allowSet(filterKeys)

	cookies := make([]*eh.Cookie, 0, len(kv))
	for name, val := range kv {
		if allow != nil {
			if _, ok := allow[name]; !ok {
				continue
			}
		}
		// KV-only as requested
		cookies = append(cookies, &eh.Cookie{Name: name, Value: val})
	}

	if len(cookies) == 0 {
		return fmt.Errorf("no cookies matched filter for %q / %q", sessionKey, domain)
	}

	std.Jar.SetCookies(u, cookies)
	return nil
}

func upsertCookies(sessionKey, domain string, cookies map[string]string, filterKeys []string) error {
	if sessionKey == "" {
		return fmt.Errorf("sessionKey is empty")
	}
	if domain == "" {
		return fmt.Errorf("domain is empty")
	}
	if len(cookies) == 0 {
		return fmt.Errorf("cookies map is empty")
	}

	allow := allowSet(filterKeys)

	fileMu.Lock()
	defer fileMu.Unlock()

	store, err := readStoreLocked()
	if err != nil {
		return fmt.Errorf("read cookies store: %w", err)
	}

	if store[sessionKey] == nil {
		store[sessionKey] = map[string]map[string]string{}
	}
	if store[sessionKey][domain] == nil {
		store[sessionKey][domain] = map[string]string{}
	}

	dst := store[sessionKey][domain]
	for k, v := range cookies {
		if allow != nil {
			if _, ok := allow[k]; !ok {
				continue
			}
		}
		dst[k] = v
	}

	return writeStoreLocked(store)
}

func saveClientCookies(client *surf.Client, sessionKey, domain string, filterKeys []string) error {
	if client == nil {
		return fmt.Errorf("client is nil")
	}

	std := client.GetClient()
	if std == nil || std.Jar == nil {
		return fmt.Errorf("client has no cookie jar; ensure you used Builder().Session()")
	}

	u, err := normalizeBaseURL(domain)
	if err != nil {
		return fmt.Errorf("invalid domain %q: %w", domain, err)
	}

	allow := allowSet(filterKeys)

	// IMPORTANT: returns []*eh.Cookie
	cs := std.Jar.Cookies(u)

	kv := make(map[string]string, len(cs))
	for _, c := range cs {
		if c == nil || c.Name == "" {
			continue
		}
		if allow != nil {
			if _, ok := allow[c.Name]; !ok {
				continue
			}
		}
		kv[c.Name] = c.Value
	}

	if len(kv) == 0 {
		return fmt.Errorf("no cookies found in client for domain %q (after filtering)", domain)
	}

	// Write all collected keys/values
	return upsertCookies(sessionKey, domain, kv, nil)
}
