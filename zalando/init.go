package zalando

import (
	"fmt"
	"regexp"
	"strings"
	"time"
	"zalando-solutions/akamai"
	"zalando-solutions/utils"

	"github.com/enetx/g"
)

type Result struct {
	Status   int
	Msg      string
	Location string
}

func (z *zalaTask) followUpMyAccountFirst(redirect *string, secFetchSite *string) (Result, error) {
	headers := g.NewMapOrd[g.String, g.String]()
	headers.Set(":method", "")
	headers.Set(":authority", "")
	headers.Set(":scheme", "")
	headers.Set(":path", "")
	headers.Set("upgrade-insecure-requests", "1")
	headers.Set("user-agent", utils.UserAgent)
	headers.Set("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
	headers.Set("sec-ch-ua", utils.SecChUa)
	headers.Set("sec-ch-ua-mobile", "?0")
	headers.Set("sec-ch-ua-platform", `"Windows"`)
	headers.Set("sec-fetch-site", g.String(*secFetchSite))
	headers.Set("sec-fetch-mode", "navigate")
	headers.Set("sec-fetch-user", "?1")
	headers.Set("sec-fetch-dest", "document")
	headers.Set("referer", g.String(fmt.Sprintf("https://www.zalando.%s/", z.CountryISOCode)))
	headers.Set("accept-encoding", "gzip, deflate, br, zstd")
	headers.Set("accept-language", utils.AcceptLanguage)
	headers.Set("cookie", "")
	headers.Set("priority", "u=0, i")

	res := z.Client.
		Get(g.String(*redirect)).
		SetHeaders(headers).
		Do()

	if !res.IsOk() {
		return Result{Msg: "request failed"}, res.Err()
	}

	resp := res.Ok()
	loc := resp.Headers.Get("location")

	if resp.StatusCode == 307 && resp.GetResponse().Request.URL.Path == "/login" {
		*secFetchSite = "cross-site"
		return Result{
			Status:   resp.GetResponse().StatusCode,
			Msg:      fmt.Sprintf("Found redirect (%s)", resp.StatusCode.Text()),
			Location: string(loc),
		}, nil
	} else if resp.StatusCode == 302 && resp.GetResponse().Request.URL.Path == "/authorize" {
		return Result{
			Status:   resp.GetResponse().StatusCode,
			Msg:      fmt.Sprintf("Found redirect (%s)", resp.StatusCode.Text()),
			Location: string(loc),
		}, nil
	}

	return Result{
		Status: int(resp.StatusCode),
		Msg:    fmt.Sprintf("followUpMyAccountFirst request failed (%v)", resp.StatusCode),
	}, HTTPError{Code: int(resp.StatusCode), Msg: resp.GetResponse().Status}
}

func (z *zalaTask) followUpMyAccountSecond(redirect *string) (Result, error) {
	headers := g.NewMapOrd[g.String, g.String]()
	headers.Set(":method", "")
	headers.Set(":authority", "")
	headers.Set(":scheme", "")
	headers.Set(":path", "")
	headers.Set("upgrade-insecure-requests", "1")
	headers.Set("user-agent", utils.UserAgent)
	headers.Set("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
	headers.Set("sec-fetch-site", "cross-site")
	headers.Set("sec-fetch-mode", "navigate")
	headers.Set("sec-fetch-user", "?1")
	headers.Set("sec-fetch-dest", "document")
	headers.Set("sec-ch-ua", utils.SecChUa)
	headers.Set("sec-ch-ua-mobile", "?0")
	headers.Set("sec-ch-ua-platform", `"Windows"`)
	headers.Set("referer", g.String(fmt.Sprintf("https://www.zalando.%s/", z.CountryISOCode)))
	headers.Set("accept-encoding", "gzip, deflate, br, zstd")
	headers.Set("accept-language", utils.AcceptLanguage)
	headers.Set("cookie", "")
	headers.Set("priority", "u=0, i")

	res := z.Client.
		Get(g.String(*redirect)).
		SetHeaders(headers).
		Do()

	if !res.IsOk() {
		return Result{Msg: "request failed"}, res.Err()
	}

	resp := res.Ok()
	loc := resp.Headers.Get("location")

	if resp.StatusCode == 302 {
		return Result{
			Status:   resp.GetResponse().StatusCode,
			Msg:      fmt.Sprintf("Found redirect (%s)", resp.StatusCode.Text()),
			Location: string(loc),
		}, nil
	} else if resp.StatusCode == 200 && resp.GetResponse().Request.URL.Path == "/authenticate" {
		bodyBytes := resp.Body.Bytes()
		if len(bodyBytes) == 0 {
			return Result{Msg: "empty body"}, fmt.Errorf("empty body")
		}

		re := regexp.MustCompile(`https://accounts\.zalando\.com/authenticate\?[^"' <>\n]+`)
		raw := re.FindString(string(bodyBytes))
		if raw == "" {
			return Result{Msg: "auth url not found"}, fmt.Errorf("referer not found")
		}
		raw = strings.ReplaceAll(raw, `\u0026`, `&`)
		authURL, err := buildAuthenticateURLOrdered(raw)
		if err != nil {
			return Result{Msg: "auth url normalize failed"}, err
		}
		z.Akamai.Referer = authURL
		z.Akamai.Sensor.PageUrl = resp.GetResponse().Request.URL.String()
		z.Akamai.Sbsd.PageUrl = resp.GetResponse().Request.URL.String()
		z.Akamai.Sensor.SensorPath, err = akamai.ParseScriptPathSensor(bodyBytes)
		if err != nil {
			return Result{
				Status: 400,
				Msg:    fmt.Sprintf("cant get sensorpath for parsescript (%s)", err),
			}, err
		}
		z.Akamai.Sbsd.SbsdPath, z.Akamai.Sbsd.SbsdV, err = akamai.ParseScriptPathSbsd(bodyBytes)
		if err != nil {
			return Result{
				Status: 400,
				Msg:    fmt.Sprintf("cant get sbsdpath for parsescript (%s)", err),
			}, err
		}
		z.Akamai.Pixel.Bazadebezolkohpepadr, z.Akamai.Pixel.PixelScriptUrl, err = akamai.ParsePixel(bodyBytes)
		if err != nil {
			return Result{
				Status: 400,
				Msg:    fmt.Sprintf("cant get bazade for pixel ParsePixel (%s)", err),
			}, err
		}
		return Result{
			Status:   resp.GetResponse().StatusCode,
			Msg:      fmt.Sprintf("Finished redirects (%s)", resp.StatusCode.Text()),
			Location: string(loc),
		}, nil
	}

	return Result{
		Status: int(resp.StatusCode),
		Msg:    fmt.Sprintf("followUpMyAccountSecond request failed (%v)", resp.StatusCode),
	}, HTTPError{Code: int(resp.StatusCode), Msg: resp.GetResponse().Status}
}
func (z *zalaTask) init() (Result, error) {
	domain := fmt.Sprintf("https://www.zalando.%s", strings.ToLower(z.CountryISOCode))
	headers := g.NewMapOrd[g.String, g.String]()
	headers.Set(":method", "")
	headers.Set(":authority", "")
	headers.Set(":scheme", "")
	headers.Set(":path", "")
	headers.Set("sec-ch-ua", utils.SecChUa)
	headers.Set("sec-ch-ua-mobile", "?0")
	headers.Set("sec-ch-ua-platform", `"Windows"`)
	headers.Set("upgrade-insecure-requests", "1")
	headers.Set("user-agent", utils.UserAgent)
	headers.Set("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
	headers.Set("sec-fetch-site", "none")
	headers.Set("sec-fetch-mode", "navigate")
	headers.Set("sec-fetch-user", "?1")
	headers.Set("sec-fetch-dest", "document")
	headers.Set("accept-encoding", "gzip, deflate, br, zstd")
	headers.Set("accept-language", utils.AcceptLanguage)
	headers.Set("cookie", "")
	headers.Set("priority", "u=0, i")

	res := z.Client.
		Get(g.String(domain)).
		SetHeaders(headers).
		Do()

	if !res.IsOk() {
		return Result{Msg: "request failed"}, res.Err()
	}
	resp := res.Ok()
	if resp.StatusCode == 200 {
		// bodyBytes := resp.Body.Bytes()
		// if len(bodyBytes) == 0 {
		// 	return Result{Msg: "empty body"}, fmt.Errorf("empty body")
		// }

		// finalURL := domain
		// z.Akamai.Referer = finalURL
		// z.Akamai.Sensor.PageUrl = finalURL
		// z.Akamai.Sbsd.PageUrl = finalURL
		// var err error

		// z.Akamai.Sensor.SensorPath, err = akamai.ParseScriptPathSensor(bodyBytes)
		// if err != nil {
		// 	return Result{
		// 		Status: 400,
		// 		Msg:    fmt.Sprintf("cant get sensorpath for parsescript (%s)", err),
		// 	}, err
		// }
		// z.Akamai.Sbsd.SbsdPath, z.Akamai.Sbsd.SbsdV, err = akamai.ParseScriptPathSbsd(bodyBytes)
		// if err != nil {
		// 	return Result{
		// 		Status: 400,
		// 		Msg:    fmt.Sprintf("cant get sbsdpath for parsescript (%s)", err),
		// 	}, err
		// }
		// z.Akamai.Pixel.Bazadebezolkohpepadr, z.Akamai.Pixel.PixelScriptUrl, err = akamai.ParsePixel(bodyBytes)
		// if err != nil {
		// 	return Result{
		// 		Status: 400,
		// 		Msg:    fmt.Sprintf("cant get bazade for pixel ParsePixel (%s)", err),
		// 	}, err
		// }
		return Result{
			Status: 200,
			Msg:    "Homepage fetched (OK)",
		}, nil
	} else {
		return Result{
			Status: int(resp.StatusCode),
			Msg:    fmt.Sprintf("Init request failed (%v)", resp.StatusCode),
		}, HTTPError{Code: int(resp.StatusCode), Msg: resp.GetResponse().Status}
	}
}

func (z *zalaTask) firstRequest(redirect *string) (Result, error) {
	headers := g.NewMapOrd[g.String, g.String]()
	headers.Set(":method", "")
	headers.Set(":authority", "")
	headers.Set(":scheme", "")
	headers.Set(":path", "")
	headers.Set("sec-ch-ua", utils.SecChUa)
	headers.Set("sec-ch-ua-mobile", "?0")
	headers.Set("sec-ch-ua-platform", `"Windows"`)
	headers.Set("upgrade-insecure-requests", "1")
	headers.Set("user-agent", utils.UserAgent)
	headers.Set("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
	headers.Set("sec-fetch-site", "same-origin")
	headers.Set("sec-fetch-mode", "navigate")
	headers.Set("sec-fetch-user", "?1")
	headers.Set("sec-fetch-dest", "document")
	headers.Set("referer", g.String(z.Akamai.Referer))
	headers.Set("accept-encoding", "gzip, deflate, br, zstd")
	headers.Set("accept-language", utils.AcceptLanguage)
	headers.Set("cookie", "")
	headers.Set("priority", "u=0, i")

	res := z.Client.
		Get(g.String(*redirect)).
		SetHeaders(headers).
		Do()

	if !res.IsOk() {
		return Result{Msg: "request failed"}, res.Err()
	}

	resp := res.Ok()

	loc := resp.Headers.Get("location")
	if resp.StatusCode == 302 {
		return Result{
			Status:   resp.GetResponse().StatusCode,
			Msg:      fmt.Sprintf("Found redirect (%s)", resp.StatusCode.Text()),
			Location: string(loc),
		}, nil
	}

	return Result{
		Status: resp.GetResponse().StatusCode,
		Msg:    fmt.Sprintf("Redirect 302 request failed (%s)", resp.StatusCode.Text()),
	}, HTTPError{Code: resp.GetResponse().StatusCode, Msg: resp.StatusCode.Text()}
}

func ZalandoInit(t *utils.Task) {
	z := NewClient(t)
	_ = z.ChangeTaskProxy()

	res, err := z.retryLogic("getPublicIP", z.getPublicIP)
	if err != nil {
		utils.LogError(z.TaskNumber, "getPublicIP", fmt.Sprintf("final status=%d msg=%q", res.Status, res.Msg), err)
		return
	}

	err = z.checkIfSessionExists("www.zalando.pl", []string{"zsso", "zsso-p"})
	if err != nil {
		if err.Error() == "not found" {
			utils.LogDebug(z.TaskNumber, "ZalandoInit", "Session not found, logging in")
			err := z.loginFlow()
			if err != nil {
				utils.LogError(z.TaskNumber, "login", "cant login", err)
				return
			}
		} else {
			utils.LogError(z.TaskNumber, "checkIfSessionExists", "cant read session data", err)
			return
		}
	}
	utils.LogInfo(z.TaskNumber, "ZalandoInit", "Session found")

	utils.LogInfo(z.TaskNumber, "ZalandoInit", "Successfully prepared zalandoinit")
	time.Sleep(1 * time.Hour)
}
