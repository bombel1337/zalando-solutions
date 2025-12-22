package utils

import (
	"bufio"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"time"
)

func init() {
	// Ensures rotation is actually random across runs.
	rand.Seed(time.Now().UnixNano())
}

func loadProxies(filename string) ([]string, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var proxies []string
	sc := bufio.NewScanner(f)

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		proxies = append(proxies, line)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return proxies, nil
}

func (t *Task) ChangeTaskProxy() error {
	if strings.TrimSpace(t.DebugIP) != "" {
		t.setCurrentProxy(t.DebugIP)
		return nil
	}

	if len(t.ProxyList) == 0 {
		t.setCurrentProxy("")
		return nil
	}

	raw, err := getRandomProxy(t.ProxyList)
	if err != nil {
		return err
	}

	proxyURL, err := normalizeProxyToURL(raw)
	if err != nil {
		return err
	}

	t.setCurrentProxy(proxyURL)
	return nil
}
func (t *Task) CurrentProxy() string {
	t.proxyMu.RLock()
	defer t.proxyMu.RUnlock()
	return t.currentProxy
}
func (t *Task) setCurrentProxy(proxyURL string) {
	t.proxyMu.Lock()
	t.currentProxy = proxyURL
	t.proxyMu.Unlock()
}

func normalizeProxyToURL(p string) (string, error) {
	p = strings.TrimSpace(p)
	if p == "" {
		return "", fmt.Errorf("empty proxy")
	}

	if strings.Contains(p, "://") {
		return p, nil
	}

	parts := strings.Split(p, ":")
	if len(parts) != 4 {
		return "", fmt.Errorf("invalid proxy format (expected host:port:user:pass or URL): %q", p)
	}
	host, port, user, pass := parts[0], parts[1], parts[2], parts[3]
	if host == "" || port == "" || user == "" || pass == "" {
		return "", fmt.Errorf("invalid proxy parts (empty field): %q", p)
	}

	return fmt.Sprintf("http://%s:%s@%s:%s", user, pass, host, port), nil
}

func getRandomProxy(proxies []string) (string, error) {
	if len(proxies) == 0 {
		return "", fmt.Errorf("no proxies available")
	}
	return proxies[rand.Intn(len(proxies))], nil
}
