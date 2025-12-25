package zalando

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"strings"
	"zalando-solutions/utils"

	"github.com/enetx/g"
	// "encoding/json"
	// "fmt"
	// "io"
	// "math/rand"
	// "strings"
	// "zalando-solutions/utils"
	// http "github.com/bogdanfinn/fhttp"
)

func (z *zalaTask) consents() (Result, error) {
	zcid, _ := getQuery(z.Akamai.Referer, "zalando_client_id")

	headers := g.NewMapOrd[g.String, g.String]()
	headers.Set(":method", "")
	headers.Set(":authority", "")
	headers.Set(":scheme", "")
	headers.Set(":path", "")
	headers.Set("x-frontend-type", "browser")
	headers.Set("sec-ch-ua-platform", `"Windows"`)
	headers.Set("viewport-width", "1920")
	headers.Set("sec-ch-ua", utils.SecChUa)
	headers.Set("x-zalando-client-id", g.String(zcid))
	headers.Set("sec-ch-ua-mobile", "?0")
	headers.Set("dpr", "1")
	headers.Set("user-agent", utils.UserAgent)
	headers.Set("content-type", "application/json")
	headers.Set("accept", "*/*")
	headers.Set("sec-fetch-site", "same-origin")
	headers.Set("sec-fetch-mode", "cors")
	headers.Set("sec-fetch-dest", "empty")
	headers.Set("referer", g.String(z.Akamai.Sensor.PageUrl))
	headers.Set("accept-encoding", "gzip, deflate, br, zstd")
	headers.Set("accept-language", utils.AcceptLanguage)
	headers.Set("cookie", "")
	headers.Set("priority", "u=1, i")

	res := z.Client.
		Get("https://accounts.zalando.com/api/sso/consents").
		SetHeaders(headers).
		Do()

	if !res.IsOk() {
		return Result{Msg: "request failed"}, res.Err()
	}
	resp := res.Ok()
	if resp.StatusCode == 404 {
		return Result{
			Status: int(resp.StatusCode),
			Msg:    fmt.Sprintf("Successfully fetched (%s)", resp.GetResponse().Status),
		}, nil
	}

	return Result{
		Msg: fmt.Sprintf("Fetch failed (%s)", resp.GetResponse().Status),
	}, HTTPError{Code: int(resp.StatusCode), Msg: resp.GetResponse().Status}
}

func (z *zalaTask) checkCredentials() (Result, error) {
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
		"email":  z.Data.ZalandoEmail,
		"secret": z.Data.ZalandoPassword,
	})
	if err != nil {
		return Result{Msg: "marshal failed"}, err
	}
	res := z.Client.
		Post("https://accounts.zalando.com/api/sso/credentials-check", b).
		SetHeaders(headers).
		SetHeaders("x-xsrf-token", "").
		Do()

	if !res.IsOk() {
		return Result{Msg: "request failed"}, res.Err()
	}

	resp := res.Ok()

	if resp.StatusCode == 200 {
		type checkCredentialsStruct struct {
			Category    string `json:"category"`
			Description string `json:"description"`
		}
		var response checkCredentialsStruct
		resp.Body.JSON(&response)

		if response.Description == "Strong enough" {
			return Result{
				Status: int(resp.StatusCode),
				Msg:    fmt.Sprintf("Successfully fetched (%s)", resp.GetResponse().Status),
			}, nil
		} else {
			return Result{Msg: "bad body response"}, fmt.Errorf(response.Description)
		}
	}

	return Result{
		Status: int(resp.StatusCode),
		Msg:    fmt.Sprintf("checkCredentials request failed (%s)", resp.GetResponse().Status),
	}, HTTPError{Code: int(resp.StatusCode), Msg: resp.GetResponse().Status}
}

func (z *zalaTask) register() (Result, error) {
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

	first := z.FirstNames[rand.Intn(len(z.FirstNames))]
	last := z.LastNames[rand.Intn(len(z.LastNames))]
	rid, _ := getQuery(z.Akamai.Referer, "request_id")
	tc, _ := getQuery(z.Akamai.Referer, "tc")

	b, err := json.Marshal(map[string]any{
		"email":                        z.Data.ZalandoEmail,
		"secret":                       z.Data.ZalandoPassword,
		"first_name":                   first,
		"last_name":                    last,
		"accepts_terms_and_conditions": true,
		"authentication_request": map[string]any{
			"client_id":    "fashion-store-web",
			"request_id":   rid,
			"redirect_uri": fmt.Sprintf("https://www.zalando.%s/sso/callback", z.CountryISOCode),
			"ui_locales":   fmt.Sprintf("%s-%s", z.CountryISOCode, strings.ToUpper(z.CountryISOCode)),
			"tc":           tc,
		},
	})
	if err != nil {
		return Result{Msg: "marshal failed"}, err
	}
	res := z.Client.
		Post("https://accounts.zalando.com/api/sso/registrations", b).
		SetHeaders(headers).
		SetHeaders("x-xsrf-token", "").
		Do()

	if !res.IsOk() {
		return Result{Msg: "request failed"}, res.Err()
	}

	resp := res.Ok()
	if resp.StatusCode == 204 {
		return Result{
			Status: int(resp.StatusCode),
			Msg:    fmt.Sprintf("Successfully fetched (%s)", resp.GetResponse().Status),
		}, nil
	}

	return Result{
		Status: int(resp.StatusCode),
		Msg:    fmt.Sprintf("register request failed (%s)", resp.GetResponse().Status),
	}, HTTPError{Code: int(resp.StatusCode), Msg: resp.GetResponse().Status}
}
