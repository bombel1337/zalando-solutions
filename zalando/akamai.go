package zalando

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strings"
	"zalando-solutions/akamai"
	"zalando-solutions/utils"

	tls_client "github.com/bogdanfinn/tls-client"

	"github.com/Hyper-Solutions/hyper-sdk-go/v2"
	http "github.com/bogdanfinn/fhttp"
)

func (t *task) getPublicIP() (Result, error) {
	req, err := http.NewRequest(http.MethodGet, "https://api.ipify.org?format=json", nil)
	if err != nil {
		return Result{Msg: "build request failed"}, err
	}
	resp, err := t.Client.Do(req)
	if err != nil {
		return Result{Msg: "request failed"}, err
	}
	defer resp.Body.Close()
	type ipifyResp struct {
		IP string `json:"ip"`
	}
	if resp.StatusCode == 200 {
		var out ipifyResp
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			return Result{Msg: "decode failed"}, err
		}
		if out.IP == "" {
			return Result{Msg: "empty ip in response"}, err
		}
		t.Akamai.IPAddress = out.IP
		return Result{
			Status: resp.StatusCode,
			Msg:    fmt.Sprintf("Successfully fetched (%s)", resp.Status),
		}, nil
	}

	return Result{
		Status: resp.StatusCode,
		Msg:    fmt.Sprintf("GetPublicIP request failed (%s)", resp.Status),
	}, HTTPError{Code: resp.StatusCode, Msg: resp.Status}
}
func (t *task) visitSensorScriptAkamai() (Result, error) {

	req, err := http.NewRequest(http.MethodGet, t.Akamai.Sensor.SensorScriptUrl, nil)
	if err != nil {
		return Result{Msg: "build request failed"}, err
	}

	req.Header = http.Header{
		"sec-ch-ua-platform": {`"Windows"`},
		"dpr":                {"1"},
		"viewport-width":     {"1920"},
		"user-agent":         {utils.UserAgent},
		"sec-ch-ua":          {utils.SecChUa},
		"sec-ch-ua-mobile":   {"?0"},
		"accept":             {"*/*"},
		"sec-fetch-site":     {"same-origin"},
		"sec-fetch-mode":     {"no-cors"},
		"sec-fetch-dest":     {"script"},
		"referer":            {t.Akamai.Referer},
		"accept-encoding":    {"gzip, deflate, br, zstd"},
		"accept-language":    {utils.AcceptLanguage},
		"priority":           {"u=0, i"},
		http.HeaderOrderKey: {
			"sec-ch-ua-platform",
			"dpr",
			"viewport-width",
			"user-agent",
			"sec-ch-ua",
			"sec-ch-ua-mobile",
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
	if resp.StatusCode == 200 {
		t.Akamai.Sensor.SensorScriptString = string(bodyText)
		return Result{
			Status: resp.StatusCode,
			Msg:    fmt.Sprintf("Successfully fetched (%s)", resp.Status),
		}, nil
	}

	return Result{
		Status: resp.StatusCode,
		Msg:    fmt.Sprintf("VisitSensorScript request failed (%s)", resp.Status),
	}, HTTPError{Code: resp.StatusCode, Msg: resp.Status}
}
func (t *task) visitSbsdScriptAkamai() (Result, error) {
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s?v=%s", t.Akamai.Sbsd.SbsdScriptUrl, t.Akamai.Sbsd.SbsdV), nil)
	if err != nil {
		return Result{Msg: "build request failed"}, err
	}

	req.Header = http.Header{
		"sec-ch-ua-platform": {`"Windows"`},
		"dpr":                {"1"},
		"viewport-width":     {"1920"},
		"user-agent":         {utils.UserAgent},
		"sec-ch-ua":          {utils.SecChUa},
		"sec-ch-ua-mobile":   {"?0"},
		"accept":             {"*/*"},
		"sec-fetch-site":     {"same-origin"},
		"sec-fetch-mode":     {"no-cors"},
		"sec-fetch-dest":     {"script"},
		"referer":            {t.Akamai.Referer},
		"accept-encoding":    {"gzip, deflate, br, zstd"},
		"accept-language":    {utils.AcceptLanguage},
		http.HeaderOrderKey: {
			"sec-ch-ua-platform",
			"dpr",
			"viewport-width",
			"user-agent",
			"sec-ch-ua",
			"sec-ch-ua-mobile",
			"accept",
			"sec-fetch-site",
			"sec-fetch-mode",
			"sec-fetch-dest",
			"referer",
			"accept-encoding",
			"accept-language",
			"cookie",
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
		t.Akamai.Sbsd.SbsdScriptString = string(bodyText)
		return Result{
			Status: resp.StatusCode,
			Msg:    fmt.Sprintf("Successfully fetched (%s)", resp.Status),
		}, nil
	}

	return Result{
		Status: resp.StatusCode,
		Msg:    fmt.Sprintf("VisiSbsdScript request failed (%s)", resp.Status),
	}, HTTPError{Code: resp.StatusCode, Msg: resp.Status}
}
func (t *task) visitPixelScriptAkamai() (Result, error) {
	req, err := http.NewRequest(http.MethodGet, t.Akamai.Pixel.PixelScriptUrl, nil)
	if err != nil {
		return Result{Msg: "build request failed"}, err
	}

	req.Header = http.Header{
		"sec-ch-ua-platform": {`"Windows"`},
		"dpr":                {"1"},
		"viewport-width":     {"1920"},
		"user-agent":         {utils.UserAgent},
		"sec-ch-ua":          {utils.SecChUa},
		"sec-ch-ua-mobile":   {"?0"},
		"accept":             {"*/*"},
		"sec-fetch-site":     {"same-origin"},
		"sec-fetch-mode":     {"no-cors"},
		"sec-fetch-dest":     {"script"},
		"referer":            {t.Akamai.Referer},
		"accept-encoding":    {"gzip, deflate, br, zstd"},
		"accept-language":    {utils.AcceptLanguage},
		"if-none-match":      {fmt.Sprintf("%x", sha256.Sum256([]byte("etag")))},
		"if-modified-since":  {`Thu, 22 Feb 2024 19:37:35 GMT`},
		http.HeaderOrderKey: {
			"sec-ch-ua-platform",
			"dpr",
			"viewport-width",
			"user-agent",
			"sec-ch-ua",
			"sec-ch-ua-mobile",
			"accept",
			"sec-fetch-site",
			"sec-fetch-mode",
			"sec-fetch-dest",
			"referer",
			"accept-encoding",
			"accept-language",
			"cookie",
			"if-none-match",
			"if-modified-since",
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

	if resp.StatusCode == 200 {
		t.Akamai.Pixel.U, err = akamai.ParsePixelScriptVar(resp.Body)
		if err != nil {
			return Result{Msg: "read body failed"}, err
		}

		return Result{
			Status: resp.StatusCode,
			Msg:    fmt.Sprintf("Successfully fetched (%s)", resp.Status),
		}, nil
	}

	return Result{
		Status: resp.StatusCode,
		Msg:    fmt.Sprintf("visitPixelScript request failed (%s)", resp.Status),
	}, HTTPError{Code: resp.StatusCode, Msg: resp.Status}
}
func (t *task) postAkamaiSensor(sensorData *string) error {
	b, _ := json.Marshal(map[string]string{"sensor_data": *sensorData})
	body := bytes.NewReader(b)

	req, err := http.NewRequest(http.MethodPost, t.Akamai.Sensor.SensorScriptUrl, body)
	if err != nil {
		return err
	}

	req.Header = http.Header{
		"sec-ch-ua-platform": {`"Windows"`},
		"dpr":                {"1"},
		"viewport-width":     {"1920"},
		"user-agent":         {utils.UserAgent},
		"sec-ch-ua":          {utils.SecChUa},
		"content-type":       {"text/plain;charset=UTF-8"},
		"sec-ch-ua-mobile":   {"?0"},
		"accept":             {"*/*"},
		"origin":             {t.Akamai.Domain},
		"sec-fetch-site":     {"same-origin"},
		"sec-fetch-mode":     {"cors"},
		"sec-fetch-dest":     {"empty"},
		"referer":            {t.Akamai.Referer},
		"accept-encoding":    {"gzip, deflate, br, zstd"},
		"accept-language":    {utils.AcceptLanguage},
		"priority":           {"u=1, i"},
		http.HeaderOrderKey: {
			"content-length",
			"sec-ch-ua-platform",
			"dpr",
			"viewport-width",
			"user-agent",
			"sec-ch-ua",
			"content-type",
			"sec-ch-ua-mobile",
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
		return err
	}
	defer resp.Body.Close()
	bodyText, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode == 201 {
		if strings.Contains(string(bodyText), `{"success": true}`) {
			return nil
		} else {
			return fmt.Errorf("bad body on post sensor")
		}
	}

	return fmt.Errorf("request failed: %s", resp.Status)
}

func (t *task) postSbsdPayload(payload *string) error {
	b, _ := json.Marshal(map[string]string{"body": *payload})
	body := bytes.NewReader(b)
	req, err := http.NewRequest(http.MethodPost, t.Akamai.Sbsd.SbsdScriptUrl, body)
	if err != nil {
		return err
	}

	req.Header = http.Header{
		"sec-ch-ua-platform": {`"Windows"`},
		"dpr":                {"1"},
		"viewport-width":     {"1920"},
		"user-agent":         {utils.UserAgent},
		"sec-ch-ua":          {utils.SecChUa},
		"content-type":       {"application/json"},
		"sec-ch-ua-mobile":   {"?0"},
		"accept":             {"*/*"},
		"origin":             {t.Akamai.Domain},
		"sec-fetch-site":     {"same-origin"},
		"sec-fetch-mode":     {"cors"},
		"sec-fetch-dest":     {"empty"},
		"referer":            {t.Akamai.Referer},
		"accept-encoding":    {"gzip, deflate, br, zstd"},
		"accept-language":    {utils.AcceptLanguage},
		"priority":           {"u=1, i"},
		http.HeaderOrderKey: {
			"content-length",
			"sec-ch-ua-platform",
			"dpr",
			"viewport-width",
			"user-agent",
			"sec-ch-ua",
			"content-type",
			"sec-ch-ua-mobile",
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
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 202 || resp.StatusCode == 200 {
		return nil
	}

	return fmt.Errorf("request failed: %s", resp.Status)
}

func (t *task) postPixelPayload(payload *string) error {
	body := strings.NewReader(*payload)
	url, err := addPixelPrefix(t.Akamai.Pixel.PixelScriptUrl)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, url, body)
	if err != nil {
		return err
	}

	req.Header = http.Header{
		"sec-ch-ua-platform": {`"Windows"`},
		"dpr":                {"1"},
		"viewport-width":     {"1920"},
		"user-agent":         {utils.UserAgent},
		"sec-ch-ua":          {utils.SecChUa},
		"content-type":       {"application/x-www-form-urlencoded"},
		"sec-ch-ua-mobile":   {"?0"},
		"accept":             {"*/*"},
		"origin":             {t.Akamai.Domain},
		"sec-fetch-site":     {"same-origin"},
		"sec-fetch-mode":     {"cors"},
		"sec-fetch-dest":     {"empty"},
		"referer":            {t.Akamai.Referer},
		"accept-encoding":    {"gzip, deflate, br, zstd"},
		"accept-language":    {utils.AcceptLanguage},
		"priority":           {"u=1, i"},
		http.HeaderOrderKey: {
			"content-length",
			"sec-ch-ua-platform",
			"dpr",
			"viewport-width",
			"user-agent",
			"sec-ch-ua",
			"content-type",
			"sec-ch-ua-mobile",
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
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		return nil
	}

	return fmt.Errorf("request failed: %s", resp.Status)
}

func getCookieValue(client tls_client.HttpClient, rawUrl string, key string) (string, error) {
	parsedURL, err := url.Parse(rawUrl)
	if err != nil {
		return "", err
	}

	for _, cookie := range client.GetCookies(parsedURL) {
		if cookie.Name == key {
			return cookie.Value, nil
		}
	}

	return "", fmt.Errorf("cookie not found: " + key)
}
func (t *task) generateValidAkamaiSensor() error {
	context := ""
	sensorData := ""
	for i := range 3 {
		_abck, err := getCookieValue(t.Client, t.Akamai.Domain, "_abck")
		if err != nil {
			return fmt.Errorf("could not find _abck cookie: %s", err.Error())
		}
		bm_sz, err := getCookieValue(t.Client, t.Akamai.Domain, "bm_sz")
		if err != nil {
			return fmt.Errorf("could not find bm_sz cookie: %s", err.Error())
		}
		input := hyper.SensorInput{
			ScriptUrl:      t.Akamai.Sensor.SensorScriptUrl,
			PageUrl:        fmt.Sprintf("%s", t.Akamai.Sensor.PageUrl),
			UserAgent:      utils.UserAgent,
			Abck:           _abck,
			Bmsz:           bm_sz,
			Version:        "3",
			AcceptLanguage: utils.AcceptLanguage,
			IP:             t.Akamai.IPAddress,
		}
		if i == 0 {
			input.Script = t.Akamai.Sensor.SensorScriptString
		} else {
			input.Context = context
		}
		// fmt.Println("input sensor======")
		// b, err := json.Marshal(input)
		// if err != nil {
		// 	return fmt.Errorf("error generating sbsd payload: %s", err.Error())
		// } else {
		// 	fmt.Printf("input sensor=%s]n", b)
		// }
		sensorData, context, err = akamai.GenerateSensorData(t.Akamai.AkamaiClient, &input)
		if err != nil {
			return fmt.Errorf("error generating sensordata: %s", err.Error())
		}
		// fmt.Println("sensor ==================")
		// fmt.Println(sensorData, context)
		// fmt.Println("sensor ==================")

		err = t.postAkamaiSensor(&sensorData)
		if err != nil {
			return fmt.Errorf("error posting sensordata: %s", err.Error())
		}

		_abck, err = getCookieValue(t.Client, "https://accounts.zalando.com", "_abck")
		if err != nil {
			return fmt.Errorf("could not find _abck cookie: %s", err.Error())
		}
		if akamai.IsCookieValid(_abck, i) {
			fmt.Println("abck valid on step", i)
			return nil
		}

	}
	return nil
}

func (t *task) generateValidAkamaiSbsd() error {
	for i := range 2 {
		bm_so, err := getCookieValue(t.Client, "https://accounts.zalando.com", "bm_so")
		if err != nil {
			return fmt.Errorf("could not find bm_so cookie: %s", err.Error())
		}

		input := hyper.SbsdInput{
			Index:          i,
			UserAgent:      utils.UserAgent,
			Uuid:           t.Akamai.Sbsd.SbsdV,
			PageUrl:        t.Akamai.Sensor.PageUrl,
			OCookie:        bm_so,
			Script:         t.Akamai.Sbsd.SbsdScriptString,
			AcceptLanguage: utils.AcceptLanguage,
			IP:             t.Akamai.IPAddress,
		}
		// fmt.Println("input sbsd======")
		// b, err := json.Marshal(input)
		// if err != nil {
		// 	return fmt.Errorf("error generating sbsd payload: %s", err.Error())
		// } else {
		// 	fmt.Printf("input sbsd=%s]n", b)
		// }
		payload, err := akamai.GenerateSbsdPayload(t.Akamai.AkamaiClient, &input)
		if err != nil {
			return fmt.Errorf("error generating sbsd payload: %s", err.Error())
		}
		// fmt.Println("sbsd ==================")

		// fmt.Println(payload)
		// fmt.Println("sbsd ==================")

		err = t.postSbsdPayload(&payload)
		if err != nil {
			return fmt.Errorf("error posting sbsd payload: %s", err.Error())
		}
	}
	return nil
}

func (t *task) generateValidAkamaiPixel() error {

	input := hyper.PixelInput{
		UserAgent:      utils.UserAgent,
		HTMLVar:        t.Akamai.Pixel.Bazadebezolkohpepadr,
		ScriptVar:      t.Akamai.Pixel.U,
		AcceptLanguage: utils.AcceptLanguage,
		IP:             t.Akamai.IPAddress,
	}
	payload, err := akamai.GeneratePixel(t.Akamai.AkamaiClient, &input)
	if err != nil {
		return fmt.Errorf("error generating sbsd payload: %s", err.Error())
	}
	fmt.Println("pixel ==================")

	fmt.Println(payload)
	fmt.Println("pixel ==================")

	err = t.postPixelPayload(&payload)
	if err != nil {
		return fmt.Errorf("error posting pixel payload: %s", err.Error())
	}

	return nil
}
