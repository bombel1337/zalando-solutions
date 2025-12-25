package zalando

import (
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"strings"
	"time"
	"zalando-solutions/utils"

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

	res := z.Client.
		Post("https://accounts.zalando.com/api/sso/username-lookup", b).
		SetHeaders(headers).
		SetHeaders("x-xsrf-token", "").
		Do()

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

		return Result{
			Status:   int(resp.StatusCode),
			Msg:      fmt.Sprintf("Successfully fetched (%s)", resp.GetResponse().Status),
			Location: response.Next,
		}, nil

	} else if resp.StatusCode == 403 {
		return Result{Msg: "akamai ban"}, HTTPError{Code: int(resp.StatusCode), Msg: resp.GetResponse().Status}
	}

	return Result{
		Status: int(resp.StatusCode),
		Msg:    fmt.Sprintf("usernameLookup request failed (%s)", resp.GetResponse().Status),
	}, HTTPError{Code: int(resp.StatusCode), Msg: resp.GetResponse().Status}
}
func (z *zalaTask) login() (Result, error) {
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

	clientID, _ := getQuery(z.Akamai.Referer, "client_id")
	requestID, _ := getQuery(z.Akamai.Referer, "request_id")
	redirectURI, _ := getQuery(z.Akamai.Referer, "redirect_uri")
	uiLocales, _ := getQuery(z.Akamai.Referer, "ui_locales")
	tc, _ := getQuery(z.Akamai.Referer, "tc")

	type bodystruct struct {
		Secret                string `json:"secret"`
		Email                 string `json:"email"`
		AuthenticationRequest struct {
			ClientID    string `json:"client_id"`
			RequestID   string `json:"request_id"`
			RedirectURI string `json:"redirect_uri"`
			UiLocales   string `json:"ui_locales"`
			Tc          string `json:"tc"`
		}
	}
	body := bodystruct{
		Secret: z.Data.ZalandoPassword,
		Email:  z.Data.ZalandoEmail,
		AuthenticationRequest: struct {
			ClientID    string `json:"client_id"`
			RequestID   string `json:"request_id"`
			RedirectURI string `json:"redirect_uri"`
			UiLocales   string `json:"ui_locales"`
			Tc          string `json:"tc"`
		}{
			ClientID:    clientID,
			RequestID:   requestID,
			RedirectURI: redirectURI,
			UiLocales:   uiLocales,
			Tc:          tc,
		},
	}

	b, err := json.Marshal(body)
	if err != nil {
		return Result{Msg: "marshal failed"}, err
	}

	res := z.Client.
		Post("https://accounts.zalando.com/api/sso/authentications/credentials", b).
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

	} else {
		return Result{
			Status: int(resp.StatusCode),
			Msg:    fmt.Sprintf("login request failed (%s)", resp.GetResponse().Status),
		}, HTTPError{Code: int(resp.StatusCode), Msg: resp.GetResponse().Status}
	}
}
func (z *zalaTask) loginFlow() error {
	res, err := z.retryLogic("init", z.init)
	if err != nil {
		utils.LogError(z.TaskNumber, "login", fmt.Sprintf("final status=%d msg=%q", res.Status, res.Msg), err)
		return err
	}

	z.Akamai.Referer = fmt.Sprintf("https://www.zalando.%s/", z.CountryISOCode)
	redirect := fmt.Sprintf("https://www.zalando.%s/myaccount/orders", strings.ToLower(z.CountryISOCode))
	res, err = z.retryLogic("firstRequest", func() (Result, error) {
		res, e := z.firstRequest(&redirect)
		return res, e
	})
	if err != nil {
		utils.LogError(z.TaskNumber, "firstRequest", fmt.Sprintf("final status=%d msg=%q, location=%s", res.Status, res.Msg, res.Location), err)
		return err
	}

	secFetchSite := "same-origin"
	redirect = fmt.Sprintf("https://www.zalando.%s%s", strings.ToLower(z.CountryISOCode), res.Location)
	res, err = z.retryLogic("followUpMyAccountFirst", func() (Result, error) {
		res, e := z.followUpMyAccountFirst(&redirect, &secFetchSite)
		return res, e
	})
	if err != nil {
		utils.LogError(z.TaskNumber, "followUpMyAccountFirst", fmt.Sprintf("final status=%d msg=%q, location=%s", res.Status, res.Msg, res.Location), err)
		return err
	}

	redirect = res.Location
	res, err = z.retryLogic("followUpMyAccountFirst", func() (Result, error) {
		res, e := z.followUpMyAccountFirst(&redirect, &secFetchSite)
		return res, e
	})
	if err != nil {
		utils.LogError(z.TaskNumber, "followUpMyAccountFirst", fmt.Sprintf("final status=%d msg=%q, location=%s", res.Status, res.Msg, res.Location), err)
		return err
	}

	redirect = fmt.Sprintf("https://accounts.zalando.com%s", res.Location)
	res, err = z.retryLogic("followUpMyAccountSecond", func() (Result, error) {
		res, e := z.followUpMyAccountSecond(&redirect)
		return res, e
	})

	redirect = fmt.Sprintf("https://accounts.zalando.com%s", res.Location)
	res, err = z.retryLogic("followUpMyAccountSecond", func() (Result, error) {
		res, e := z.followUpMyAccountSecond(&redirect)
		return res, e
	})

	res, err = z.retryLogic("consents", z.consents)
	if err != nil {
		utils.LogError(z.TaskNumber, "consents", fmt.Sprintf("final status=%d msg=%q", res.Status, res.Msg), err)
		return err
	}
	z.Akamai.Domain = "https://accounts.zalando.com"

	z.Akamai.Sensor.SensorScriptUrl = fmt.Sprintf("https://accounts.zalando.com%s", z.Akamai.Sensor.SensorPath)
	res, err = z.retryLogic("visitSensorScriptAkamai", z.visitSensorScriptAkamai)
	if err != nil {
		utils.LogError(z.TaskNumber, "visitSensorScriptAkamai", fmt.Sprintf("final status=%d msg=%q, location=%s", res.Status, res.Msg, res.Location), err)
		return err
	}
	z.Akamai.Sbsd.SbsdScriptUrl = fmt.Sprintf("https://accounts.zalando.com%s", z.Akamai.Sbsd.SbsdPath)
	res, err = z.retryLogic("visitSbsdScriptAkamai", z.visitSbsdScriptAkamai)
	if err != nil {
		utils.LogError(z.TaskNumber, "visitSbsdScriptAkamai", fmt.Sprintf("final status=%d msg=%q, location=%s", res.Status, res.Msg, res.Location), err)
		return err
	}
	err = z.generateValidAkamaiSensor()
	if err != nil {
		utils.LogError(z.TaskNumber, "generateValidAkamaiSensor", fmt.Sprintf("msg=%q", err), err)
		return err
	}

	err = z.generateValidAkamaiSbsd()
	if err != nil {
		utils.LogError(z.TaskNumber, "generateValidAkamaiSbsd", fmt.Sprintf("msg=%q", err), err)
		return err
	}
	// res, err = z.retryLogic("visitPixelScriptAkamai", z.visitPixelScriptAkamai)
	// if err != nil {
	// 	utils.LogError(z.TaskNumber, "visitPixelScriptAkamai", fmt.Sprintf("final status=%d msg=%q, location=%s", res.Status, res.Msg, res.Location), err)
	// 	return
	// }

	// err = z.generateValidAkamaiPixel()
	// if err != nil {
	// 	utils.LogError(z.TaskNumber, "generateValidAkamaiSbsd", fmt.Sprintf("msg=%q", err), err)
	// 	return
	// }

	z.Data.CsrfToken, err = getCookieValue(z.Client, "https://accounts.zalando.com", "csrf-token")
	if err != nil {
		utils.LogError(z.TaskNumber, "getCookieValue", fmt.Sprintf("msg=%q", err), err)
		return err
	}
	time.Sleep(z.Delay)

	res, err = z.retryLogic("usernameLookup", z.usernameLookup)
	if err != nil {
		utils.LogError(z.TaskNumber, "usernameLookup", fmt.Sprintf("final status=%d msg=%q, location=%s", res.Status, res.Msg, res.Location), err)
		return err
	}
	if res.Location != "login" {
		utils.LogError(z.TaskNumber, "usernameLookup ", fmt.Sprintf("bad response from usernameLookup loc=%s", res.Location), fmt.Errorf(res.Location))
		return fmt.Errorf(res.Location)
	}

	z.Akamai.Referer = strings.Replace(z.Akamai.Referer, "&view=verify-email", "", 1)
	res, err = z.retryLogic("login", z.login)
	if err != nil {
		utils.LogError(z.TaskNumber, "login", fmt.Sprintf("final status=%d msg=%q, location=%s", res.Status, res.Msg, res.Location), err)
		return err
	}

	redirect = fmt.Sprintf("%s&view=login", strings.Replace(z.Akamai.Referer, "authenticate", "sso/authenticate", 1))
	res, err = z.retryLogic("firstRequest", func() (Result, error) {
		res, e := z.firstRequest(&redirect)
		return res, e
	})
	if err != nil {
		utils.LogError(z.TaskNumber, "firstRequest", fmt.Sprintf("final status=%d msg=%q, location=%s", res.Status, res.Msg, res.Location), err)
		return err
	}
	fmt.Println(res.Location)
	cookieKey := fmt.Sprintf("%s:%s", z.Data.ZalandoEmail, z.Data.ZalandoPassword)
	err = saveClientCookies(z.Client, cookieKey, "accounts.zalando.com", []string{"zsso", "zsso-p"})
	if err != nil {
		utils.LogError(z.TaskNumber, "login", "saveClientCookies failed", err)
		return err
	}
	return nil
}
