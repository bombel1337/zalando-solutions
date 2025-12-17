package utils

import (
	"bufio"
	"fmt"
	"math/rand"
	"os"
	"strings"
)

func loadProxies(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var proxies []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		proxy := scanner.Text()
		if proxy != "" {
			proxies = append(proxies, proxy)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return proxies, nil
}

func (t *Task) ChangeTaskProxy() error {
	if t.DebugIP != "" {
		return t.Client.SetProxy(t.DebugIP)
	}

	rotatedRandomProxy, err := rotateRandomProxy(t.ProxyList) // []string
	if err != nil {
		return err
	}
	return t.Client.SetProxy(rotatedRandomProxy)
}

func rotateRandomProxy(proxies []string) (string, error) {
	p, err := getRandomProxy(proxies)
	if err != nil {
		return "", err
	}

	// Expect: host:port:user:pass
	parts := strings.Split(p, ":")
	if len(parts) != 4 {
		return "", fmt.Errorf("invalid proxy format (expected host:port:user:pass): %q", p)
	}

	host, port, user, pass := parts[0], parts[1], parts[2], parts[3]
	return fmt.Sprintf("http://%s:%s@%s:%s", user, pass, host, port), nil
}

func getRandomProxy(proxies []string) (string, error) {
	if len(proxies) == 0 {
		return "", fmt.Errorf("no proxies available")
	}
	return proxies[rand.Intn(len(proxies))], nil
}
