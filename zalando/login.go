package zalando

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"zalando-solutions/utils"

	http "github.com/bogdanfinn/fhttp"
)

func (t *task) usernameLookup() (Result, error) {
	payload := strings.NewReader(fmt.Sprintf(`{"email":"%s"}`, t.Data.ZalandoEmail))

	req, err := http.NewRequest(http.MethodPost, "https://accounts.zalando.com/api/sso/username-lookup", payload)
	if err != nil {
		return Result{Msg: "build request failed"}, err
	}

	req.Header = http.Header{
		"ot-tracer-spanid":   {`a09c5aca4b43e763`}, //{fmt.Sprintf("%016x", rand.Uint64())},
		"sec-ch-ua-platform": {`"Windows"`},
		"x-csrf-token":       {t.Data.CsrfToken},
		"x-xsrf-token":       {""},
		"viewport-width":     {"1920"},
		"sec-ch-ua":          {utils.SecChUa},
		"sec-ch-ua-mobile":   {"?0"},
		"ot-tracer-sampled":  {"true"},
		"ot-tracer-traceid":  {`93e9e4915087b384`}, //{fmt.Sprintf("%016x", rand.Uint64())},
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
		type usernameLookupNext struct {
			Next string `json:"next"`
		}
		var response usernameLookupNext
		err = json.Unmarshal([]byte(bodyText), &response)
		if err != nil {
			return Result{Msg: "unmarshal failed"}, err
		}
		if response.Next == "login" || response.Next == "registration" || response.Next == "error-locked" {
			return Result{
				Status:   resp.StatusCode,
				Msg:      fmt.Sprintf("Successfully fetched (%s)", resp.Status),
				Location: response.Next,
			}, nil
		} else {
			return Result{Msg: "bad response"}, fmt.Errorf(response.Next)
		}
	} else if resp.StatusCode == 403 {
		return Result{Msg: "akamai ban"}, HTTPError{Code: resp.StatusCode, Msg: resp.Status}
	}

	return Result{
		Msg: fmt.Sprintf("Fetch failed (%s)", string(bodyText)),
	}, HTTPError{Code: resp.StatusCode, Msg: resp.Status}
}
