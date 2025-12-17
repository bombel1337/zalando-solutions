package zalando

import (
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"strings"
	"zalando-solutions/utils"

	http "github.com/bogdanfinn/fhttp"
)

func (t *task) consents() (Result, error) {

	req, err := http.NewRequest(http.MethodGet, "https://accounts.zalando.com/api/sso/consents", nil)
	if err != nil {
		return Result{Msg: "build request failed"}, err
	}
	zcid, _ := getQuery(t.Akamai.Referer, "zalando_client_id")

	req.Header = http.Header{
		"x-frontend-type":     {"browser"},
		"sec-ch-ua-platform":  {`"Windows"`},
		"viewport-width":      {"1920"},
		"sec-ch-ua":           {utils.SecChUa},
		"x-zalando-client-id": {zcid},
		"sec-ch-ua-mobile":    {"?0"},
		"dpr":                 {"1"},
		"user-agent":          {utils.UserAgent},
		"content-type":        {"application/json"},
		"accept":              {"*/*"},
		"sec-fetch-site":      {"same-origin"},
		"sec-fetch-mode":      {"cors"},
		"sec-fetch-dest":      {"empty"},
		"referer":             {t.Akamai.Sensor.PageUrl},
		"accept-encoding":     {"gzip, deflate, br, zstd"},
		"accept-language":     {utils.AcceptLanguage},
		"priority":            {"u=1, i"},
		http.HeaderOrderKey: {
			"x-frontend-type",
			"sec-ch-ua-platform",
			"viewport-width",
			"sec-ch-ua",
			"x-zalando-client-id",
			"sec-ch-ua-mobile",
			"dpr",
			"user-agent",
			"content-type",
			"accept",
			"sec-fetch-site",
			"sec-fetch-mode",
			"sec-fetch-dest",
			"referer",
			"accept-encoding",
			"accept-language",
			"cookie",
			"priority",
		},
		http.PHeaderOrderKey: {
			":method",
			":authority",
			":scheme",
			":path",
		},
	}

	resp, err := t.Client.Do(req)
	if err != nil {
		return Result{Msg: "request failed"}, err
	}

	defer resp.Body.Close()
	bodyText, err := io.ReadAll(resp.Body)
	if err != nil {
		return Result{Msg: "read body failed"}, err
	}

	if resp.StatusCode == 404 {
		return Result{
			Status:   resp.StatusCode,
			Msg:      fmt.Sprintf("Successfully fetched (%s)", resp.Status),
		}, nil
	}

	return Result{
		Msg: fmt.Sprintf("Fetch failed (%s)", string(bodyText)),
	}, HTTPError{Code: resp.StatusCode, Msg: resp.Status}
}
func (t *task) checkCredentials() (Result, error) {
	payload := strings.NewReader(fmt.Sprintf(`{"email":"%s","secret":"%s"}`, t.Data.ZalandoEmail, t.Data.ZalandoPassword))

	req, err := http.NewRequest(http.MethodPost, "https://accounts.zalando.com/api/sso/credentials-check", payload)
	if err != nil {
		return Result{Msg: "build request failed"}, err
	}

	req.Header = http.Header{
		"ot-tracer-spanid":   {fmt.Sprintf("%016x", rand.Uint64())},
		"sec-ch-ua-platform": {`"Windows"`},
		"x-csrf-token":       {t.Data.CsrfToken},
		"x-xsrf-token":       {""},
		"viewport-width":     {"1920"},
		"sec-ch-ua":          {utils.SecChUa},
		"sec-ch-ua-mobile":   {"?0"},
		"ot-tracer-sampled":  {"true"},
		"ot-tracer-traceid":  {fmt.Sprintf("%016x", rand.Uint64())},
		"dpr":                {"1"},
		"user-agent":         {utils.UserAgent},
		"content-type":       {"application/json"},
		"accept":             {"*/*"},
		"origin":             {"https://accounts.zalando.com"},
		"sec-fetch-site":     {"same-origin"},
		"sec-fetch-mode":     {"cors"},
		"sec-fetch-dest":     {"empty"},
		"referer":            {t.Akamai.Referer},
		"accept-encoding":    {"gzip, deflate, br, zstd"},
		"accept-language":    {utils.AcceptLanguage},
		"priority":           {"u=1, i"},
		http.HeaderOrderKey: {
			"content-length",
			"ot-tracer-spanid",
			"sec-ch-ua-platform",
			"x-csrf-token",
			"x-xsrf-token",
			"viewport-width",
			"sec-ch-ua",
			"sec-ch-ua-mobile",
			"ot-tracer-sampled",
			"ot-tracer-traceid",
			"dpr",
			"user-agent",
			"content-type",
			"accept",
			"origin",
			"sec-fetch-site",
			"sec-fetch-mode",
			"sec-fetch-dest",
			"referer",
			"accept-encoding",
			"accept-language",
			"cookie",
			"priority",
		},
		http.PHeaderOrderKey: {
			":method",
			":authority",
			":scheme",
			":path",
		},
	}

	resp, err := t.Client.Do(req)
	if err != nil {
		return Result{Msg: "request failed"}, err
	}

	defer resp.Body.Close()
	bodyText, err := io.ReadAll(resp.Body)
	if err != nil {
		return Result{Msg: "read body failed"}, err
	}

	if resp.StatusCode == 200 {
		type checkCredentialsStruct struct {
			Category    string `json:"category"`
			Description string `json:"description"`
		}
		var response checkCredentialsStruct
		err = json.Unmarshal([]byte(bodyText), &response)
		if err != nil {
			return Result{Msg: "unmarshal failed"}, err
		}
		if response.Description == "Strong enough" {
			return Result{
				Status:   resp.StatusCode,
				Msg:      fmt.Sprintf("Successfully fetched (%s)", resp.Status),
				Location: response.Description,
			}, nil
		} else {
			return Result{Msg: "bad response"}, fmt.Errorf(response.Description)
		}
	}

	return Result{
		Msg: fmt.Sprintf("Fetch failed (%s)", string(bodyText)),
	}, HTTPError{Code: resp.StatusCode, Msg: resp.Status}
}
func (t *task) register() (Result, error) {
	first := t.FirstNames[rand.Intn(len(t.FirstNames))]
	last := t.LastNames[rand.Intn(len(t.LastNames))]
	rid, _ := getQuery(t.Akamai.Referer, "request_id")
	tc, _ := getQuery(t.Akamai.Referer, "tc")

	payload := strings.NewReader(fmt.Sprintf(`{"email":"%s","secret":"%s","first_name":"%s","last_name":"%s","accepts_terms_and_conditions":true,"authentication_request":{"client_id":"fashion-store-web","request_id":"%s","redirect_uri":"https://www.zalando.%s/sso/callback","ui_locales":"%s-%s","tc":"%s"}}`, t.Data.ZalandoEmail, t.Data.ZalandoPassword, first, last, rid, t.CountryISOCode, t.CountryISOCode, strings.ToUpper(t.CountryISOCode), tc))

	req, err := http.NewRequest(http.MethodPost, "https://accounts.zalando.com/api/sso/registrations", payload)
	if err != nil {
		return Result{Msg: "build request failed"}, err
	}

	req.Header = http.Header{
		"ot-tracer-spanid":   {fmt.Sprintf("%016x", rand.Uint64())},
		"sec-ch-ua-platform": {`"Windows"`},
		"x-csrf-token":       {t.Data.CsrfToken},
		"x-xsrf-token":       {""},
		"viewport-width":     {"1920"},
		"sec-ch-ua":          {utils.SecChUa},
		"sec-ch-ua-mobile":   {"?0"},
		"ot-tracer-sampled":  {"true"},
		"ot-tracer-traceid":  {fmt.Sprintf("%016x", rand.Uint64())},
		"dpr":                {"1"},
		"user-agent":         {utils.UserAgent},
		"content-type":       {"application/json"},
		"accept":             {"*/*"},
		"origin":             {"https://accounts.zalando.com"},
		"sec-fetch-site":     {"same-origin"},
		"sec-fetch-mode":     {"cors"},
		"sec-fetch-dest":     {"empty"},
		"referer":            {t.Akamai.Referer},
		"accept-encoding":    {"gzip, deflate, br, zstd"},
		"accept-language":    {utils.AcceptLanguage},
		"priority":           {"u=1, i"},
		http.HeaderOrderKey: {
			"content-length",
			"ot-tracer-spanid",
			"sec-ch-ua-platform",
			"x-csrf-token",
			"x-xsrf-token",
			"viewport-width",
			"sec-ch-ua",
			"sec-ch-ua-mobile",
			"ot-tracer-sampled",
			"ot-tracer-traceid",
			"dpr",
			"user-agent",
			"content-type",
			"accept",
			"origin",
			"sec-fetch-site",
			"sec-fetch-mode",
			"sec-fetch-dest",
			"referer",
			"accept-encoding",
			"accept-language",
			"cookie",
			"priority",
		},
		http.PHeaderOrderKey: {
			":method",
			":authority",
			":scheme",
			":path",
		},
	}

	resp, err := t.Client.Do(req)
	if err != nil {
		return Result{Msg: "request failed"}, err
	}

	defer resp.Body.Close()

	if resp.StatusCode == 204 {
		return Result{
			Status: resp.StatusCode,
			Msg:    fmt.Sprintf("Successfully fetched (%s)", resp.Status),
		}, nil
	}

	return Result{
		Msg: fmt.Sprintf("Fetch failed (%s)", resp.Status),
	}, HTTPError{Code: resp.StatusCode, Msg: resp.Status}
}
