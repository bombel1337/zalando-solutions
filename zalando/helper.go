package zalando

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

func getClientMutationID() string {
	ms := time.Now().UnixMilli()
	s := strconv.FormatInt(ms, 10)
	var b strings.Builder
	for i, r := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteString("Â\u00A0")
		}
		b.WriteRune(r)
	}
	return b.String()
}
func getQuery(authURL, key string) (string, error) {
	u, err := url.Parse(authURL)
	if err != nil {
		return "", err
	}
	return u.Query().Get(key), nil
}
func buildAuthenticateURLOrdered(rawAuthURL string) (string, error) {
	u, err := url.Parse(rawAuthURL)
	if err != nil {
		return "", fmt.Errorf("parse auth url: %w", err)
	}

	base := "https://accounts.zalando.com"
	path := "/authenticate"

	rawMap := parseRawQuery(u.RawQuery)

	order := []string{
		"redirect_uri",
		"client_id",
		"response_type",
		"scope",
		"request_id",
		"nonce",
		"state",
		"premise",
		"ui_locales",
		"zalando_client_id",
		"tc",
		"appearance",
		"sales_channel",
		"client_country",
		"client_category",
		"view",
	}

	parts := make([]string, 0, len(order))
	for _, k := range order {
		v, ok := rawMap[k]
		if !ok || v == "" {
			return "", fmt.Errorf("missing query param %q in auth url", k)
		}
		parts = append(parts, k+"="+v)
	}

	return base + path + "?" + strings.Join(parts, "&"), nil
}
func buildSSOPostReg(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	m := map[string]string{}
	for _, p := range strings.Split(u.RawQuery, "&") {
		k, v, _ := strings.Cut(p, "=")
		if _, ok := m[k]; !ok {
			m[k] = v
		}
	}
	u.Scheme, u.Host, u.Path, u.Fragment = "https", "accounts.zalando.com", "/sso/authenticate", ""
	u.RawQuery = "redirect_uri=" + m["redirect_uri"] + "&client_id=" + m["client_id"] + "&response_type=" + m["response_type"] + "&scope=" + m["scope"] +
		"&request_id=" + m["request_id"] + "&nonce=" + m["nonce"] + "&state=" + m["state"] + "&premise=" + m["premise"] + "&ui_locales=" + m["ui_locales"] +
		"&zalando_client_id=" + m["zalando_client_id"] + "&tc=" + m["tc"] + "&sales_channel=" + m["sales_channel"] + "&client_country=" + m["client_country"] +
		"&client_category=" + m["client_category"] + "&view=register"
	return u.String(), nil
}
func parseRawQuery(raw string) map[string]string {
	out := make(map[string]string, 16)
	if raw == "" {
		return out
	}
	for _, kv := range strings.Split(raw, "&") {
		if kv == "" {
			continue
		}
		k, v, found := strings.Cut(kv, "=")
		if !found {
			if _, exists := out[k]; !exists {
				out[k] = ""
			}
			continue
		}
		if _, exists := out[k]; exists {
			continue
		}
		out[k] = v
	}
	return out
}

func addPixelPrefix(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}

	p := u.Path
	trailingSlash := strings.HasSuffix(p, "/")
	p = strings.TrimSuffix(p, "/")

	i := strings.LastIndex(p, "/")
	if i < 0 || i == len(p)-1 {
		return "", fmt.Errorf("invalid path: %q", u.Path)
	}

	last := p[i+1:]
	u.Path = p[:i+1] + "pixel_" + last
	if trailingSlash {
		u.Path += "/"
	}

	return u.String(), nil
}

func decodeBodyByEncoding(contentEncoding string, raw []byte) ([]byte, error) {
	enc := strings.ToLower(strings.TrimSpace(contentEncoding))
	if enc == "" || enc == "identity" {
		return raw, nil
	}

	rd := bytes.NewReader(raw)

	switch enc {
	case "gzip":
		gr, err := gzip.NewReader(rd)
		if err != nil {
			return nil, fmt.Errorf("gzip.NewReader: %w", err)
		}
		defer gr.Close()
		return io.ReadAll(gr)

	case "deflate":
		fr := flate.NewReader(rd)
		defer fr.Close()
		return io.ReadAll(fr)

	case "br":
		br := brotli.NewReader(rd)
		return io.ReadAll(br)

	case "zstd":
		zr, err := zstd.NewReader(rd)
		if err != nil {
			return nil, fmt.Errorf("zstd.NewReader: %w", err)
		}
		defer zr.Close()
		return io.ReadAll(zr)

	default:
		return nil, fmt.Errorf("unsupported Content-Encoding: %q", enc)
	}
}
