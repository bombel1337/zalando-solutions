package zalando

import (
	"encoding/json"
	"fmt"


	"github.com/enetx/g"
	// "encoding/json"
	// "fmt"
	// "io"
	// "strings"
	// "zalando-solutions/utils"
	// http "github.com/bogdanfinn/fhttp"
)

func (z *zalaTask) usernameLookup() (Result, error) {
	headers := g.NewMapOrd[g.String, g.String]()
	headers.Set(":method", "")
	headers.Set(":authority", "")
	headers.Set(":scheme", "")
	headers.Set(":path", "")
	headers.Set("content-length", "")
	headers.Set("ot-tracer-spanid", g.String(fmt.Sprintf("%016x", rand.Uint64())))
	headers.Set("sec-ch-ua-platform", `"Windows"`)
	headers.Set("x-csrf-token", g.String(z.Data.CsrfToken))
	headers.Set("x-xsrf-token", "")
	headers.Set("viewport-width", "1920")
	headers.Set("sec-ch-ua", utils.SecChUa)
	headers.Set("sec-ch-ua-mobile", "?0")
	headers.Set("ot-tracer-sampled", "true")
	headers.Set("ot-tracer-traceid", g.String(fmt.Sprintf("%016x", rand.Uint64())))
	headers.Set("dpr", "1")
	headers.Set("user-agent", utils.UserAgent)
	headers.Set("content-type", "application/json")
	headers.Set("accept", "*/*")
	headers.Set("origin", "https://accounts.zalando.com")
	headers.Set("sec-fetch-site", "same-origin")
	headers.Set("sec-fetch-mode", "cors")
	headers.Set("sec-fetch-dest", "empty")
	headers.Set("referer", g.String(z.Akamai.Referer))
	headers.Set("accept-encoding", "gzip, deflate, br, zstd")
	headers.Set("accept-language", utils.AcceptLanguage)
	headers.Set("cookie", "")
	headers.Set("priority", "u=1, i")

	b, err := json.Marshal(map[string]string{
		"email": z.Data.ZalandoEmail,
	})
	if err != nil {
		return Result{Msg: "marshal failed"}, err
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

	if !res.IsOk() {
		return Result{Msg: "request failed"}, res.Err()
	}

	resp := res.Ok()
	if resp.StatusCode == 200 {
		type usernameLookupNext struct {
			Next string `json:"next"`
		}
		var response usernameLookupNext
		resp.Body.JSON(&response)

		if response.Next == "login" || response.Next == "registration" || response.Next == "error-locked" {
			return Result{
				Status:   int(resp.StatusCode),
				Msg:      fmt.Sprintf("Successfully fetched (%s)", resp.GetResponse().Status),
				Location: response.Next,
			}, nil
		} else {
			return Result{Msg: "bad response"}, fmt.Errorf(response.Next)
		}
	} else if resp.StatusCode == 403 {
		return Result{Msg: "akamai ban"}, HTTPError{Code: int(resp.StatusCode), Msg: resp.GetResponse().Status}
	}

	return Result{
		Status: int(resp.StatusCode),
		Msg:    fmt.Sprintf("usernameLookup request failed (%s)", resp.GetResponse().Status),
	}, HTTPError{Code: int(resp.StatusCode), Msg: resp.GetResponse().Status}
}
