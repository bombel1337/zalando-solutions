package zalando

import (
	"fmt"
	"net/url"
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

	fmt.Println(resp.GetResponse().Request.URL)
	if resp.StatusCode == 307 && resp.GetResponse().Request.URL.Path == "/login" {
		fmt.Printf("Redirect: %s -> Location: %s\n", resp.StatusCode.Text(), loc)
		*secFetchSite = "cross-site"
		return Result{
			Status:   resp.GetResponse().StatusCode,
			Msg:      fmt.Sprintf("Found redirect (%s)", resp.StatusCode.Text()),
			Location: string(loc),
		}, nil
	} else if resp.StatusCode == 302 && resp.GetResponse().Request.URL.Path == "/authorize" {
		fmt.Printf("Redirect: %s -> Location: %s\n", resp.StatusCode.Text(), loc)
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
		fmt.Println(resp.GetResponse().Request.URL.String())
		fmt.Println(raw)
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
		fmt.Println(z.Akamai.Pixel.Bazadebezolkohpepadr, z.Akamai.Pixel.PixelScriptUrl)
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
		bodyBytes := resp.Body.Bytes()
		if len(bodyBytes) == 0 {
			return Result{Msg: "empty body"}, fmt.Errorf("empty body")
		}

		finalURL := domain
		z.Akamai.Referer = finalURL
		z.Akamai.Sensor.PageUrl = finalURL
		z.Akamai.Sbsd.PageUrl = finalURL
		var err error

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
		fmt.Printf("Redirect: %s -> Location: %s\n", resp.StatusCode.Text(), loc)

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

	res, err = z.retryLogic("init", z.init)
	if err != nil {
		utils.LogError(z.TaskNumber, "init", fmt.Sprintf("final status=%d msg=%q", res.Status, res.Msg), err)
		return
	}

	// time.Sleep(t.Delay)
	// z.Akamai.Sensor.SensorScriptUrl = fmt.Sprintf("https://www.zalando.%s%s", z.CountryISOCode, z.Akamai.Sbsd.SbsdPath)
	// res, err = z.retryLogic("visitSensorScriptAkamai", z.visitSensorScriptAkamai)
	// if err != nil {
	// 	utils.LogError(z.TaskNumber, "visitSensorScriptAkamai", fmt.Sprintf("final status=%d msg=%q, location=%s", res.Status, res.Msg, res.Location), err)
	// 	return
	// }

	// z.Akamai.Sbsd.SbsdScriptUrl = fmt.Sprintf("https://www.zalando.%s%s", z.CountryISOCode, z.Akamai.Sbsd.SbsdPath)
	// res, err = z.retryLogic("visitSbsdScriptAkamai", z.visitSbsdScriptAkamai)
	// if err != nil {
	// 	utils.LogError(z.TaskNumber, "visitSbsdScriptAkamai", fmt.Sprintf("final status=%d msg=%q, location=%s", res.Status, res.Msg, res.Location), err)
	// 	return
	// }
	// time.Sleep(t.Delay)
	z.Akamai.Referer = fmt.Sprintf("https://www.zalando.%s/", z.CountryISOCode)
	redirect := fmt.Sprintf("https://www.zalando.%s/myaccount/orders", strings.ToLower(t.CountryISOCode))
	res, err = z.retryLogic("firstRequest", func() (Result, error) {
		res, e := z.firstRequest(&redirect)
		return res, e
	})
	if err != nil {
		utils.LogError(z.TaskNumber, "firstRequest", fmt.Sprintf("final status=%d msg=%q, location=%s", res.Status, res.Msg, res.Location), err)
		return
	}

	secFetchSite := "same-origin"
	redirect = fmt.Sprintf("https://www.zalando.%s%s", strings.ToLower(t.CountryISOCode), res.Location)
	res, err = z.retryLogic("followUpMyAccountFirst", func() (Result, error) {
		res, e := z.followUpMyAccountFirst(&redirect, &secFetchSite)
		return res, e
	})
	if err != nil {
		utils.LogError(z.TaskNumber, "followUpMyAccountFirst", fmt.Sprintf("final status=%d msg=%q, location=%s", res.Status, res.Msg, res.Location), err)
		return
	}

	redirect = res.Location
	res, err = z.retryLogic("followUpMyAccountFirst", func() (Result, error) {
		res, e := z.followUpMyAccountFirst(&redirect, &secFetchSite)
		return res, e
	})
	if err != nil {
		utils.LogError(z.TaskNumber, "followUpMyAccountFirst", fmt.Sprintf("final status=%d msg=%q, location=%s", res.Status, res.Msg, res.Location), err)
		return
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
		return
	}
	z.Akamai.Domain = "https://accounts.zalando.com"

	z.Akamai.Sbsd.SbsdScriptUrl = fmt.Sprintf("https://accounts.zalando.com%s", z.Akamai.Sbsd.SbsdPath)
	res, err = z.retryLogic("visitSbsdScriptAkamai", z.visitSbsdScriptAkamai)
	if err != nil {
		utils.LogError(z.TaskNumber, "visitSbsdScriptAkamai", fmt.Sprintf("final status=%d msg=%q, location=%s", res.Status, res.Msg, res.Location), err)
		return
	}
	err = z.generateValidAkamaiSbsd()
	if err != nil {
		utils.LogError(z.TaskNumber, "generateValidAkamaiSbsd", fmt.Sprintf("msg=%q", err), err)
		return
	}

	z.Akamai.Sensor.SensorScriptUrl = fmt.Sprintf("https://accounts.zalando.com%s", z.Akamai.Sensor.SensorPath)
	res, err = z.retryLogic("visitSensorScriptAkamai", z.visitSensorScriptAkamai)
	if err != nil {
		utils.LogError(z.TaskNumber, "visitSensorScriptAkamai", fmt.Sprintf("final status=%d msg=%q, location=%s", res.Status, res.Msg, res.Location), err)
		return
	}
	err = z.generateValidAkamaiSensor()
	if err != nil {
		utils.LogError(z.TaskNumber, "generateValidAkamaiSensor", fmt.Sprintf("msg=%q", err), err)
		return
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

	z.Data.CsrfToken, err = getCookieValue(t.Client, "https://accounts.zalando.com", "csrf-token")
	if err != nil {
		utils.LogError(z.TaskNumber, "getCookieValue", fmt.Sprintf("msg=%q", err), err)
		return
	}
	time.Sleep(t.Delay)

	res, err = z.retryLogic("usernameLookup", z.usernameLookup)
	if err != nil {
		utils.LogError(z.TaskNumber, "usernameLookup", fmt.Sprintf("final status=%d msg=%q, location=%s", res.Status, res.Msg, res.Location), err)
		return
	}

	u, _ := url.Parse(z.Akamai.Referer)
	q := u.Query()
	q.Del("view")
	u.RawQuery = q.Encode()
	z.Akamai.Referer = u.String()

	res, err = z.retryLogic("checkCredentials", z.checkCredentials)
	if err != nil {
		utils.LogError(z.TaskNumber, "checkCredentials", fmt.Sprintf("final status=%d msg=%q, location=%s", res.Status, res.Msg, res.Location), err)
		return
	}

	res, err = z.retryLogic("register", z.register)
	if err != nil {
		utils.LogError(z.TaskNumber, "register", fmt.Sprintf("final status=%d msg=%q", res.Status, res.Msg), err)
		return
	}
	redirect, err = buildSSOPostReg(z.Akamai.Referer)
	if err != nil {
		utils.LogError(z.TaskNumber, "buildSSOPostReg", "cant create redirect", err)
		return
	}
	fmt.Println(redirect)

	redirect = fmt.Sprintf("https://www.zalando.%s/", strings.ToLower(t.CountryISOCode))
	res, err = z.retryLogic("firstRequest", func() (Result, error) {
		res, e := z.firstRequest(&redirect)
		return res, e
	})
	if err != nil {
		utils.LogError(z.TaskNumber, "firstRequest", fmt.Sprintf("final status=%d msg=%q, location=%s", res.Status, res.Msg, res.Location), err)
		return
	}
	fmt.Println("final location", res.Location)

	utils.LogInfo(z.TaskNumber, "ZalandoInit", "Successfully prepared zalandoinit")
	time.Sleep(1 * time.Hour)

}
