package zalando

import (
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strings"
	"time"
	"zalando-solutions/akamai"
	"zalando-solutions/utils"

	http "github.com/bogdanfinn/fhttp"
)

type task struct {
	*utils.Task
}

func NewClient(t *utils.Task) *task {
	return &task{Task: t}
}

type Result struct {
	Status   int
	Msg      string
	Location string
}

func (t *task) followUpMyAccountFirst(redirect *string) (Result, error) {

	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s", *redirect), nil)
	if err != nil {
		return Result{Msg: "build request failed"}, err
	}

	req.Header = http.Header{
		"upgrade-insecure-requests": {"1"},
		"user-agent":                {utils.UserAgent},
		"accept":                    {"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
		"sec-ch-ua":                 {utils.SecChUa},
		"sec-ch-ua-mobile":          {"?0"},
		"sec-ch-ua-platform":        {`"Windows"`},
		"sec-fetch-site":            {"none"},
		"sec-fetch-mode":            {"navigate"},
		"sec-fetch-user":            {"?1"},
		"sec-fetch-dest":            {"document"},
		"accept-encoding":           {"gzip, deflate, br, zstd"},
		"accept-language":           {utils.AcceptLanguage},
		"priority":                  {"u=0, i"},
		http.HeaderOrderKey: {
			"upgrade-insecure-requests",
			"user-agent",
			"accept",
			"sec-ch-ua",
			"sec-ch-ua-mobile",
			"sec-ch-ua-platform",
			"sec-fetch-site",
			"sec-fetch-mode",
			"sec-fetch-user",
			"sec-fetch-dest",
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
	loc := resp.Header.Get("Location")

	if resp.StatusCode == 307 && resp.Request.URL.Path == "/login" {
		return Result{
			Status:   resp.StatusCode,
			Msg:      fmt.Sprintf("Found redirect (%s)", resp.Status),
			Location: loc,
		}, nil
	} else if resp.StatusCode == 302 {
		return Result{
			Status:   resp.StatusCode,
			Msg:      fmt.Sprintf("Found redirect (%s)", resp.Status),
			Location: loc,
		}, nil
	} else if resp.StatusCode == 200 && resp.Request.URL.Path == "/authenticate" {
		return Result{
			Status:   resp.StatusCode,
			Msg:      fmt.Sprintf("Finished redirects (%s)", resp.Status),
			Location: loc,
		}, nil
	}

	return Result{
		Location: loc,
		Status:   resp.StatusCode,
		Msg:      fmt.Sprintf("Redirect failed: %s (%s)", resp.Status, loc),
	}, HTTPError{Code: resp.StatusCode, Msg: resp.Status}
}

func (t *task) followUpMyAccountSecond(redirect *string) (Result, error) {

	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s", *redirect), nil)
	if err != nil {
		return Result{Msg: "build request failed"}, err
	}

	req.Header = http.Header{
		"upgrade-insecure-requests": {"1"},
		"user-agent":                {utils.UserAgent},
		"accept":                    {"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
		"sec-fetch-site":            {"none"},
		"sec-fetch-mode":            {"navigate"},
		"sec-fetch-user":            {"?1"},
		"sec-fetch-dest":            {"document"},
		"sec-ch-ua":                 {utils.SecChUa},
		"sec-ch-ua-mobile":          {"?0"},
		"sec-ch-ua-platform":        {`"Windows"`},
		"accept-encoding":           {"gzip, deflate, br, zstd"},
		"accept-language":           {utils.AcceptLanguage},
		"priority":                  {"u=0, i"},
		http.HeaderOrderKey: {
			"upgrade-insecure-requests",
			"user-agent",
			"accept",
			"sec-fetch-site",
			"sec-fetch-mode",
			"sec-fetch-user",
			"sec-fetch-dest",
			"sec-ch-ua",
			"sec-ch-ua-mobile",
			"sec-ch-ua-platform",
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
	loc := resp.Header.Get("Location")

	if resp.StatusCode == 307 && resp.Request.URL.Path == "/login" {
		return Result{
			Status:   resp.StatusCode,
			Msg:      fmt.Sprintf("Found redirect (%s)", resp.Status),
			Location: loc,
		}, nil
	} else if resp.StatusCode == 302 {
		return Result{
			Status:   resp.StatusCode,
			Msg:      fmt.Sprintf("Found redirect (%s)", resp.Status),
			Location: loc,
		}, nil
	} else if resp.StatusCode == 200 && resp.Request.URL.Path == "/authenticate" {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return Result{Msg: "failed to read body"}, err
		}

		re := regexp.MustCompile(`https://accounts\.zalando\.com/authenticate\?[^"' <>\n]+`)
		raw := re.FindString(string(body))
		if raw == "" {
			return Result{Msg: "auth url not found"}, fmt.Errorf("referer not found")
		}
		raw = strings.ReplaceAll(raw, `\u0026`, `&`)
		authURL, err := buildAuthenticateURLOrdered(raw)
		if err != nil {
			return Result{Msg: "auth url normalize failed"}, err
		}
		t.Akamai.Referer = authURL
		t.Akamai.Sensor.PageUrl = resp.Request.URL.String()
		t.Akamai.Sbsd.PageUrl = resp.Request.URL.String()
		t.Akamai.Sensor.SensorPath, err = akamai.ParseScriptPathSensor(body)
		if err != nil {
			return Result{
				Status: 400,
				Msg:    fmt.Sprintf("cant get sensorpath for parsescript (%s)", err),
			}, err
		}
		t.Akamai.Sbsd.SbsdPath, t.Akamai.Sbsd.SbsdV, err = akamai.ParseScriptPathSbsd(body)
		if err != nil {
			return Result{
				Status: 400,
				Msg:    fmt.Sprintf("cant get sbsdpath for parsescript (%s)", err),
			}, err
		}

		return Result{
			Status:   resp.StatusCode,
			Msg:      fmt.Sprintf("Finished redirects (%s)", resp.Status),
			Location: loc,
		}, nil
	}

	return Result{
		Location: loc,
		Status:   resp.StatusCode,
		Msg:      fmt.Sprintf("Redirect failed: %s (%s)", resp.Status, loc),
	}, HTTPError{Code: resp.StatusCode, Msg: resp.Status}
}
func (t *task) init() (Result, error) {
	domain := fmt.Sprintf("https://www.zalando.%s", strings.ToLower(t.CountryISOCode))

	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s", domain), nil)
	if err != nil {
		return Result{Msg: "build request failed"}, err
	}

	req.Header = http.Header{
		"sec-ch-ua":                 {utils.SecChUa},
		"sec-ch-ua-mobile":          {"?0"},
		"sec-ch-ua-platform":        {`"Windows"`},
		"upgrade-insecure-requests": {"1"},
		"user-agent":                {utils.UserAgent},
		"accept":                    {"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
		"sec-fetch-site":            {"none"},
		"sec-fetch-mode":            {"navigate"},
		"sec-fetch-user":            {"?1"},
		"sec-fetch-dest":            {"document"},
		"accept-encoding":           {"gzip, deflate, br, zstd"},
		"accept-language":           {utils.AcceptLanguage},
		"priority":                  {"u=0, i"},
		http.HeaderOrderKey: {
			"sec-ch-ua",
			"sec-ch-ua-mobile",
			"sec-ch-ua-platform",
			"upgrade-insecure-requests",
			"user-agent",
			"accept",
			"sec-fetch-site",
			"sec-fetch-mode",
			"sec-fetch-user",
			"sec-fetch-dest",
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
	// body, err := io.ReadAll(resp.Body)
	// if err != nil {
	// 	return Result{Msg: "failed to read body"}, err
	// }
	if resp.StatusCode == 200 {
		return Result{
			Status: resp.StatusCode,
			Msg:    fmt.Sprintf("Found redirect (%s)", resp.Status),
		}, nil
	}

	return Result{
		Status: resp.StatusCode,
		Msg:    fmt.Sprintf("Homepage request failed (%s)", resp.Status),
	}, HTTPError{Code: resp.StatusCode, Msg: resp.Status}
}
func (t *task) firstRequest() (Result, error) {
	domain := fmt.Sprintf("https://www.zalando.%s", strings.ToLower(t.CountryISOCode))

	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/myaccount/orders/", domain), nil)
	if err != nil {
		return Result{Msg: "build request failed"}, err
	}

	req.Header = http.Header{
		"sec-ch-ua":                 {utils.SecChUa},
		"sec-ch-ua-mobile":          {"?0"},
		"sec-ch-ua-platform":        {`"Windows"`},
		"upgrade-insecure-requests": {"1"},
		"user-agent":                {utils.UserAgent},
		"accept":                    {"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
		"sec-fetch-site":            {"none"},
		"sec-fetch-mode":            {"navigate"},
		"sec-fetch-user":            {"?1"},
		"sec-fetch-dest":            {"document"},
		"accept-encoding":           {"gzip, deflate, br, zstd"},
		"accept-language":           {utils.AcceptLanguage},
		"priority":                  {"u=0, i"},
		http.HeaderOrderKey: {
			"sec-ch-ua",
			"sec-ch-ua-mobile",
			"sec-ch-ua-platform",
			"upgrade-insecure-requests",
			"user-agent",
			"accept",
			"sec-fetch-site",
			"sec-fetch-mode",
			"sec-fetch-user",
			"sec-fetch-dest",
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
	loc := resp.Header.Get("Location")

	if resp.StatusCode == 302 {
		return Result{
			Status:   resp.StatusCode,
			Msg:      fmt.Sprintf("Found redirect (%s)", resp.Status),
			Location: loc,
		}, nil
	}
	// body, err := io.ReadAll(resp.Body)
	// if err != nil {
	// 	return Result{Status: 400, Msg: "failed to read body"}, err
	// }
	// fmt.Println(string(body))
	return Result{
		Status: resp.StatusCode,
		Msg:    fmt.Sprintf("Homepage request failed (%s)", resp.Status),
	}, HTTPError{Code: resp.StatusCode, Msg: resp.Status}
}

func ZalandoInit(t *utils.Task) {
	z := NewClient(t)
	// parsedURL, err := url.Parse("https://www.zalando.pl/")
	// if err != nil {
	// 	return
	// }
	// fmt.Println("===============")
	// for _, cookie := range z.Client.GetCookies(parsedURL) {
	// 	fmt.Println(cookie)
	// }
	// fmt.Println("===============")

	err := z.ChangeTaskProxy()
	if err != nil {
		utils.LogError(z.TaskNumber, "ChangeTaskProxy", "cant change proxy", err)
		return
	}
	fmt.Println(t.Client.GetProxy())

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
	time.Sleep(t.Delay)

	res, err = z.retryLogic("firstRequest", z.firstRequest)
	if err != nil {
		utils.LogError(z.TaskNumber, "firstRequest", fmt.Sprintf("final status=%d msg=%q, location=%s", res.Status, res.Msg, res.Location), err)
		return
	}

	redirect := fmt.Sprintf("https://www.zalando.%s%s", strings.ToLower(t.CountryISOCode), res.Location)
	res, err = z.retryLogic("followUpMyAccountFirst", func() (Result, error) {
		res, e := z.followUpMyAccountFirst(&redirect)
		return res, e
	})
	if err != nil {
		utils.LogError(z.TaskNumber, "followUpMyAccountFirst", fmt.Sprintf("final status=%d msg=%q, location=%s", res.Status, res.Msg, res.Location), err)
		return
	}

	redirect = res.Location
	res, err = z.retryLogic("followUpMyAccountFirst", func() (Result, error) {
		res, e := z.followUpMyAccountFirst(&redirect)
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
	if err != nil {
		utils.LogError(z.TaskNumber, "followUpMyAccountSecond", fmt.Sprintf("final status=%d msg=%q, location=%s", res.Status, res.Msg, res.Location), err)
		return
	}

	redirect = fmt.Sprintf("https://accounts.zalando.com%s", res.Location)
	res, err = z.retryLogic("followUpMyAccountSecond", func() (Result, error) {
		res, e := z.followUpMyAccountSecond(&redirect)
		return res, e
	})
	if err != nil {
		utils.LogError(z.TaskNumber, "followUpMyAccountSecond", fmt.Sprintf("final status=%d msg=%q", res.Status, res.Msg), err)
		return
	}

	res, err = z.retryLogic("consents", z.consents)
	if err != nil {
		utils.LogError(z.TaskNumber, "consents", fmt.Sprintf("final status=%d msg=%q", res.Status, res.Msg), err)
		return
	}

	z.Akamai.Sensor.SensorScriptUrl = fmt.Sprintf("https://accounts.zalando.com%s", z.Akamai.Sensor.SensorPath)
	res, err = z.retryLogic("visitSensorScriptAkamai", z.visitSensorScriptAkamai)
	if err != nil {
		utils.LogError(z.TaskNumber, "visitSensorScriptAkamai", fmt.Sprintf("final status=%d msg=%q, location=%s", res.Status, res.Msg, res.Location), err)
		return
	}

	z.Akamai.Sbsd.SbsdScriptUrl = fmt.Sprintf("https://accounts.zalando.com%s", z.Akamai.Sbsd.SbsdPath)
	res, err = z.retryLogic("visitSbsdScriptAkamai", z.visitSbsdScriptAkamai)
	if err != nil {
		utils.LogError(z.TaskNumber, "visitSbsdScriptAkamai", fmt.Sprintf("final status=%d msg=%q, location=%s", res.Status, res.Msg, res.Location), err)
		return
	}

	z.Akamai.Domain = "https://accounts.zalando.com"
	err = z.generateValidAkamaiSensor()
	if err != nil {
		utils.LogError(z.TaskNumber, "generateValidAkamaiSensor", fmt.Sprintf("msg=%q", err), err)
		return
	}
	// err = z.generateValidAkamaiSbsd()
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

	// res, err = z.retryLogic("register", z.register)
	// if err != nil {
	// 	utils.LogError(z.TaskNumber, "register", fmt.Sprintf("final status=%d msg=%q", res.Status, res.Msg), err)
	// 	return
	// }
	// redirect, err = buildSSOPostReg(z.Akamai.Referer)
	// if err != nil {
	// 	utils.LogError(z.TaskNumber, "buildSSOPostReg", "cant create redirect", err)
	// 	return
	// }
	// fmt.Println(redirect)
	utils.LogInfo(z.TaskNumber, "ZalandoInit", "Successfully prepared zalandoinit")
}
