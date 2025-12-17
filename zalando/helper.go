package zalando

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
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
	u, err := url.Parse(raw); if err != nil { return "", err }
	m := map[string]string{}
	for _, p := range strings.Split(u.RawQuery, "&") { k,v,_ := strings.Cut(p,"="); if _,ok:=m[k]; !ok { m[k]=v } }
	u.Scheme, u.Host, u.Path, u.Fragment = "https", "accounts.zalando.com", "/sso/authenticate", ""
	u.RawQuery = "redirect_uri="+m["redirect_uri"]+"&client_id="+m["client_id"]+"&response_type="+m["response_type"]+"&scope="+m["scope"]+
		"&request_id="+m["request_id"]+"&nonce="+m["nonce"]+"&state="+m["state"]+"&premise="+m["premise"]+"&ui_locales="+m["ui_locales"]+
		"&zalando_client_id="+m["zalando_client_id"]+"&tc="+m["tc"]+"&sales_channel="+m["sales_channel"]+"&client_country="+m["client_country"]+
		"&client_category="+m["client_category"]+"&view=register"
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
