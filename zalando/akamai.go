package zalando

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"zalando-solutions/akamai"
	"zalando-solutions/utils"

	"github.com/Hyper-Solutions/hyper-sdk-go/v2"
	"github.com/enetx/g"
	"github.com/enetx/surf"
)

func (z *zalaTask) getPublicIP() (Result, error) {
	headers := g.NewMapOrd[g.String, g.String]()
	headers.Set(":method", "")
	headers.Set(":authority", "")
	headers.Set(":scheme", "")
	headers.Set(":path", "")
	headers.Set("sec-ch-ua-platform", `"Windows"`)
	headers.Set("dpr", "1")
	headers.Set("viewport-width", "1920")
	headers.Set("accept", "application/json")

	type ipifyResp struct {
		IP string `json:"ip"`
	}

	res := z.Client.
		Get("https://api.ipify.org?format=json").
		SetHeaders(headers).
		Do()

	if res.IsErr() {
		err := res.Err()
		return Result{Msg: "request failed"}, err
	}

	resp := res.Ok()
	defer resp.Body.Close()

	code := int(resp.StatusCode)

	if code == 200 {
		var out ipifyResp
		if err := resp.Body.JSON(&out); err != nil {
			return Result{Status: code, Msg: "decode failed"}, err
		}

		ip := strings.TrimSpace(out.IP)
		if ip == "" {
			return Result{Status: code, Msg: "empty ip in response"}, fmt.Errorf("empty ip in response")
		}

		z.Akamai.IPAddress = ip
		return Result{
			Status: code,
			Msg:    fmt.Sprintf("Successfully fetched (status=%d)", code),
		}, nil
	}

	return Result{
		Status: code,
		Msg:    fmt.Sprintf("GetPublicIP request failed (status=%d)", code),
	}, HTTPError{Code: code, Msg: fmt.Sprintf("status=%d", code)}
}

func (z *zalaTask) visitSensorScriptAkamai() (Result, error) {
	headers := g.NewMapOrd[g.String, g.String]()
	headers.Set(":method", "")
	headers.Set(":authority", "")
	headers.Set(":scheme", "")
	headers.Set(":path", "")
	headers.Set("sec-ch-ua-platform", `"Windows"`)
	headers.Set("dpr", "1")
	headers.Set("viewport-width", "1920")
	headers.Set("user-agent", utils.UserAgent)
	headers.Set("sec-ch-ua", utils.SecChUa)
	headers.Set("sec-ch-ua-mobile", "?0")
	headers.Set("accept", "*/*")
	headers.Set("sec-fetch-site", "same-origin")
	headers.Set("sec-fetch-mode", "no-cors")
	headers.Set("sec-fetch-dest", "script")
	headers.Set("referer", g.String(z.Akamai.Referer))
	headers.Set("accept-encoding", "gzip, deflate, br, zstd")
	headers.Set("accept-language", utils.AcceptLanguage)
	headers.Set("cookie", "")
	headers.Set("priority", "u=0, i")

	res := z.Client.
		Get(g.String(z.Akamai.Sensor.SensorScriptUrl)).
		SetHeaders(headers).
		Do()

	if !res.IsOk() {
		return Result{Msg: "request failed"}, res.Err()
	}
	resp := res.Ok()
	body := resp.Body.Bytes()

	if resp.StatusCode == 200 {
		z.Akamai.Sensor.SensorScriptString = string(body)
		return Result{
			Status: int(resp.StatusCode),
			Msg:    fmt.Sprintf("Successfully fetched (%s)", resp.GetResponse().Status),
		}, nil
	}

	return Result{
		Status: int(resp.StatusCode),
		Msg:    fmt.Sprintf("visitSensorScriptAkamai request failed (%s)", resp.GetResponse().Status),
	}, HTTPError{Code: int(resp.StatusCode), Msg: resp.GetResponse().Status}
}

func (z *zalaTask) visitSbsdScriptAkamai() (Result, error) {
	headers := g.NewMapOrd[g.String, g.String]()
	headers.Set(":method", "")
	headers.Set(":authority", "")
	headers.Set(":scheme", "")
	headers.Set(":path", "")
	headers.Set("sec-ch-ua-platform", `"Windows"`)
	headers.Set("dpr", "1")
	headers.Set("viewport-width", "1920")
	headers.Set("user-agent", utils.UserAgent)
	headers.Set("sec-ch-ua", utils.SecChUa)
	headers.Set("sec-ch-ua-mobile", "?0")
	headers.Set("accept", "*/*")
	headers.Set("sec-fetch-site", "same-origin")
	headers.Set("sec-fetch-mode", "no-cors")
	headers.Set("sec-fetch-dest", "script")
	headers.Set("referer", g.String(z.Akamai.Referer))
	headers.Set("accept-encoding", "gzip, deflate, br, zstd")
	headers.Set("accept-language", utils.AcceptLanguage)
	headers.Set("cookie", "")

	res := z.Client.
		Get(g.String(fmt.Sprintf("%s?v=%s", z.Akamai.Sbsd.SbsdScriptUrl, z.Akamai.Sbsd.SbsdV))).
		SetHeaders(headers).
		Do()

	if !res.IsOk() {
		return Result{Msg: "request failed"}, res.Err()
	}
	resp := res.Ok()
	body := resp.Body.String()
	if resp.StatusCode == 200 {
		z.Akamai.Sbsd.SbsdScriptString = string(body)
		return Result{
			Status: int(resp.StatusCode),
			Msg:    fmt.Sprintf("Successfully fetched (%s)", resp.GetResponse().Status),
		}, nil
	}

	return Result{
		Status: int(resp.StatusCode),
		Msg:    fmt.Sprintf("visitSbsdScriptAkamai request failed (%s)", resp.GetResponse().Status),
	}, HTTPError{Code: int(resp.StatusCode), Msg: resp.GetResponse().Status}
}

func (z *zalaTask) visitPixelScriptAkamai() (Result, error) {
	headers := g.NewMapOrd[g.String, g.String]()
	headers.Set(":method", "")
	headers.Set(":authority", "")
	headers.Set(":scheme", "")
	headers.Set(":path", "")
	headers.Set("sec-ch-ua-platform", `"Windows"`)
	headers.Set("dpr", "1")
	headers.Set("viewport-width", "1920")
	headers.Set("user-agent", utils.UserAgent)
	headers.Set("sec-ch-ua", utils.SecChUa)
	headers.Set("sec-ch-ua-mobile", "?0")
	headers.Set("accept", "*/*")
	headers.Set("sec-fetch-site", "same-origin")
	headers.Set("sec-fetch-mode", "no-cors")
	headers.Set("sec-fetch-dest", "script")
	headers.Set("referer", g.String(z.Akamai.Referer))
	headers.Set("accept-encoding", "gzip, deflate, br, zstd")
	headers.Set("accept-language", utils.AcceptLanguage)
	headers.Set("cookie", "")
	headers.Set("if-none-match", g.String(fmt.Sprintf("%x", sha256.Sum256([]byte("etag")))))
	headers.Set("if-modified-since", "Thu, 22 Feb 2024 19:37:35 GMT")

	res := z.Client.
		Get(g.String(z.Akamai.Pixel.PixelScriptUrl)).
		SetHeaders(headers).
		Do()

	if !res.IsOk() {
		return Result{Msg: "request failed"}, res.Err()
	}
	resp := res.Ok()
	if resp.StatusCode == 200 {
		var err error
		z.Akamai.Pixel.U, err = akamai.ParsePixelScriptVar(resp.Body.Reader)
		if err != nil {
			return Result{Msg: "read body failed"}, err
		}
		return Result{
			Status: int(resp.StatusCode),
			Msg:    fmt.Sprintf("Successfully fetched (%s)", resp.GetResponse().Status),
		}, nil
	}

	return Result{
		Status: int(resp.StatusCode),
		Msg:    fmt.Sprintf("visitPixelScriptAkamai request failed (%s)", resp.GetResponse().Status),
	}, HTTPError{Code: int(resp.StatusCode), Msg: resp.GetResponse().Status}

}

func (z *zalaTask) postAkamaiSensor(sensorData *string) (Result, error) {
	headers := g.NewMapOrd[g.String, g.String]()
	headers.Set(":method", "")
	headers.Set(":authority", "")
	headers.Set(":scheme", "")
	headers.Set(":path", "")
	headers.Set("content-length", "")
	headers.Set("sec-ch-ua-platform", `"Windows"`)
	headers.Set("dpr", "1")
	headers.Set("viewport-width", "1920")
	headers.Set("user-agent", utils.UserAgent)
	headers.Set("sec-ch-ua", utils.SecChUa)
	headers.Set("content-type", "text/plain;charset=UTF-8")
	headers.Set("sec-ch-ua-mobile", "?0")
	headers.Set("accept", "*/*")
	headers.Set("origin", g.String(z.Akamai.Domain))
	headers.Set("sec-fetch-site", "same-origin")
	headers.Set("sec-fetch-mode", "cors")
	headers.Set("sec-fetch-dest", "empty")
	headers.Set("referer", g.String(z.Akamai.Referer))
	headers.Set("accept-encoding", "gzip, deflate, br, zstd")
	headers.Set("accept-language", utils.AcceptLanguage)
	headers.Set("cookie", "")
	headers.Set("priority", "u=1, i")

	b, err := json.Marshal(map[string]string{
		"sensor_data": *sensorData,
	})
	if err != nil {
		return Result{Msg: "marshal failed"}, err
	}

	res := z.Client.
		Post(g.String(z.Akamai.Sensor.SensorScriptUrl), b).
		SetHeaders(headers).
		Do()

	if !res.IsOk() {
		return Result{Msg: "request failed"}, res.Err()
	}
	resp := res.Ok()
	if resp.StatusCode == 201 {
		if z.DebugIP != "" {
			return Result{
				Status: int(resp.StatusCode),
				Msg:    fmt.Sprintf("Successfully posted sensor (%s)", resp.GetResponse().Status),
			}, nil
		}

		bodyString := resp.Body.Bytes()
		if strings.Contains(string(bodyString), `{"success": true}`) {
			return Result{
				Status: int(resp.StatusCode),
				Msg:    fmt.Sprintf("Successfully posted sensor (%s)", resp.GetResponse().Status),
			}, nil
		} else {

			return Result{Msg: fmt.Sprintf("bad body on sensor: %s", bodyString)}, fmt.Errorf(resp.GetResponse().Status)
		}
	}
	return Result{
		Status: int(resp.StatusCode),
		Msg:    fmt.Sprintf("postAkamaiSensor request failed (%s)", resp.GetResponse().Status),
	}, HTTPError{Code: int(resp.StatusCode), Msg: resp.GetResponse().Status}
}

func (z *zalaTask) postSbsdPayload(body *string) (Result, error) {
	headers := g.NewMapOrd[g.String, g.String]()
	headers.Set(":method", "")
	headers.Set(":authority", "")
	headers.Set(":scheme", "")
	headers.Set(":path", "")
	headers.Set("content-length", "")
	headers.Set("sec-ch-ua-platform", `"Windows"`)
	headers.Set("dpr", "1")
	headers.Set("viewport-width", "1920")
	headers.Set("user-agent", utils.UserAgent)
	headers.Set("sec-ch-ua", utils.SecChUa)
	headers.Set("content-type", "application/json")
	headers.Set("sec-ch-ua-mobile", "?0")
	headers.Set("accept", "*/*")
	headers.Set("origin", g.String(z.Akamai.Domain))
	headers.Set("sec-fetch-site", "same-origin")
	headers.Set("sec-fetch-mode", "cors")
	headers.Set("sec-fetch-dest", "empty")
	headers.Set("referer", g.String(z.Akamai.Referer))
	headers.Set("accept-encoding", "gzip, deflate, br, zstd")
	headers.Set("accept-language", utils.AcceptLanguage)
	headers.Set("cookie", "")
	headers.Set("priority", "u=1, i")

	b, err := json.Marshal(map[string]string{
		"body": *body,
	})
	if err != nil {
		return Result{Msg: "marshal failed"}, err
	}

	res := z.Client.
		Post(g.String(z.Akamai.Sbsd.SbsdScriptUrl), b).
		SetHeaders(headers).
		Do()

	if !res.IsOk() {
		return Result{Msg: "request failed"}, res.Err()
	}
	resp := res.Ok()

	if resp.StatusCode == 202 || resp.StatusCode == 200 {
		return Result{
			Status: int(resp.StatusCode),
			Msg:    fmt.Sprintf("Successfully posted sensor (%s)", resp.GetResponse().Status),
		}, nil
	}

	return Result{
		Status: int(resp.StatusCode),
		Msg:    fmt.Sprintf("postSbsdPayload request failed (%s)", resp.GetResponse().Status),
	}, HTTPError{Code: int(resp.StatusCode), Msg: resp.GetResponse().Status}
}

func (z *zalaTask) postPixelPayload(body *string) (Result, error) {
	url, err := addPixelPrefix(z.Akamai.Pixel.PixelScriptUrl)
	if err != nil {
		return Result{Msg: "addPixelPrefix failed"}, err
	}

	headers := g.NewMapOrd[g.String, g.String]()
	headers.Set(":method", "")
	headers.Set(":authority", "")
	headers.Set(":scheme", "")
	headers.Set(":path", "")
	headers.Set("content-length", "")
	headers.Set("sec-ch-ua-platform", `"Windows"`)
	headers.Set("dpr", "1")
	headers.Set("viewport-width", "1920")
	headers.Set("user-agent", utils.UserAgent)
	headers.Set("sec-ch-ua", utils.SecChUa)
	headers.Set("content-type", "application/x-www-form-urlencoded")
	headers.Set("sec-ch-ua-mobile", "?0")
	headers.Set("accept", "*/*")
	headers.Set("origin", g.String(z.Akamai.Domain))
	headers.Set("sec-fetch-site", "same-origin")
	headers.Set("sec-fetch-mode", "cors")
	headers.Set("sec-fetch-dest", "empty")
	headers.Set("referer", g.String(z.Akamai.Referer))
	headers.Set("accept-encoding", "gzip, deflate, br, zstd")
	headers.Set("accept-language", utils.AcceptLanguage)
	headers.Set("cookie", "")
	headers.Set("priority", "u=1, i")

	res := z.Client.
		Post(g.String(url), *body).
		SetHeaders(headers).
		Do()

	if !res.IsOk() {
		return Result{Msg: "request failed"}, res.Err()
	}
	resp := res.Ok()

	if resp.StatusCode == 200 {
		return Result{
			Status: int(resp.StatusCode),
			Msg:    fmt.Sprintf("Successfully posted pixel (%s)", resp.GetResponse().Status),
		}, nil
	}

	return Result{
		Status: int(resp.StatusCode),
		Msg:    fmt.Sprintf("postPixelPayload request failed (%s)", resp.GetResponse().Status),
	}, HTTPError{Code: int(resp.StatusCode), Msg: resp.GetResponse().Status}
}
func getCookieValue(client *surf.Client, rawURL string, key string) (string, error) {
	if client == nil || client.GetClient().Jar == nil {
		return "", nil
	}

	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}

	cookies := client.GetClient().Jar.Cookies(u)
	for _, c := range cookies {
		if c.Name == key {
			return c.Value, nil
		}
	}

	return "", nil
}

// func getCookieValue(client tls_client.HttpClient, rawUrl string, key string) (string, error) {
// 	parsedURL, err := url.Parse(rawUrl)
// 	if err != nil {
// 		return "", err
// 	}

// 	for _, cookie := range client.GetCookies(parsedURL) {
// 		if cookie.Name == key {
// 			return cookie.Value, nil
// 		}
// 	}

//		return "", fmt.Errorf("cookie not found: " + key)
//	}
func (z *zalaTask) generateValidAkamaiSensor() error {
	sensorContext := ""
	sensorData := ""
	for i := range 3 {

		_abck, err := getCookieValue(z.Client, z.Akamai.Domain, "_abck")
		if err != nil {
			return fmt.Errorf("could not find _abck cookie: %s", err.Error())
		}
		bm_sz, err := getCookieValue(z.Client, z.Akamai.Domain, "bm_sz")
		if err != nil {
			return fmt.Errorf("could not find bm_sz cookie: %s", err.Error())
		}

		input := hyper.SensorInput{
			ScriptUrl:      z.Akamai.Sensor.SensorScriptUrl,
			PageUrl:        fmt.Sprintf("%s", z.Akamai.Sensor.PageUrl),
			UserAgent:      utils.UserAgent,
			Abck:           _abck,
			Bmsz:           bm_sz,
			Version:        "3",
			AcceptLanguage: utils.AcceptLanguage,
			IP:             z.Akamai.IPAddress,
		}

		if i == 0 {
			input.Script = z.Akamai.Sensor.SensorScriptString
		} else {
			input.Context = sensorContext
		}


		sensorData, sensorContext, err = z.Akamai.AkamaiClient.GenerateSensorData(context.Background(), &input)
		if err != nil {
			println("error after GenerateSensorData")
			return fmt.Errorf("could not create sensor_data: %s", err.Error())
		}


		res, err := z.retryLogic("postAkamaiSensor", func() (Result, error) {
			res, e := z.postAkamaiSensor(&sensorData)
			return res, e
		})
		if err != nil {
			utils.LogError(z.TaskNumber, "postAkamaiSensor", fmt.Sprintf("final status=%d msg=%q", res.Status, res.Msg), err)
			return err
		}

		_abck, err = getCookieValue(z.Client, "https://accounts.zalando.com", "_abck")
		if err != nil {
			return fmt.Errorf("could not find _abck cookie: %s", err.Error())
		}
		if akamai.IsCookieValid(_abck, i) {
			utils.LogInfo(z.TaskNumber, "generateValidAkamaiSensor", fmt.Sprintf("abck valid on step=%v status=%d msg=%q", i, res.Status, res.Msg))
			return nil
		}

	}
	return nil
}

func (z *zalaTask) generateValidAkamaiSbsd() error {
	for i := range 2 {
		bm_so, err := getCookieValue(z.Client, "https://accounts.zalando.com", "bm_so")
		if err != nil {
			return fmt.Errorf("could not find bm_so cookie: %s", err.Error())
		}

		input := hyper.SbsdInput{
			Index:          i,
			UserAgent:      utils.UserAgent,
			Uuid:           z.Akamai.Sbsd.SbsdV,
			PageUrl:        z.Akamai.Sensor.PageUrl,
			OCookie:        bm_so,
			Script:         z.Akamai.Sbsd.SbsdScriptString,
			AcceptLanguage: utils.AcceptLanguage,
			IP:             z.Akamai.IPAddress,
		}

		sbsdData, err := z.Akamai.AkamaiClient.GenerateSbsdData(context.Background(), &input)
		if err != nil {
			return fmt.Errorf("error generating sbsd payload: %s", err.Error())
		}

		res, err := z.retryLogic("postSbsdPayload", func() (Result, error) {
			res, e := z.postSbsdPayload(&sbsdData)
			return res, e
		})
		if err != nil {
			utils.LogError(z.TaskNumber, "postSbsdPayload", fmt.Sprintf("final status=%d msg=%q", res.Status, res.Msg), err)
			return err
		}
	}
	return nil
}

func (z *zalaTask) generateValidAkamaiPixel() error {

	input := hyper.PixelInput{
		UserAgent:      utils.UserAgent,
		HTMLVar:        z.Akamai.Pixel.Bazadebezolkohpepadr,
		ScriptVar:      z.Akamai.Pixel.U,
		AcceptLanguage: utils.AcceptLanguage,
		IP:             z.Akamai.IPAddress,
	}

	body, err := z.Akamai.AkamaiClient.GeneratePixelData(context.Background(), &input)
	if err != nil {
		return fmt.Errorf("error generating sbsd payload: %s", err.Error())
	}


	res, err := z.retryLogic("postPixelPayload", func() (Result, error) {
		res, e := z.postPixelPayload(&body)
		return res, e
	})
	if err != nil {
		utils.LogError(z.TaskNumber, "postPixelPayload", fmt.Sprintf("final status=%d msg=%q", res.Status, res.Msg), err)
		return err
	}

	return nil
}
