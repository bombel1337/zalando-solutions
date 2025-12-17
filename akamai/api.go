package akamai

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/Hyper-Solutions/hyper-sdk-go/v2"
)

var (
	authHrefExpr = regexp.MustCompile(`(?is)"href"\s*:\s*"(https://accounts\.zalando\.com/authenticate\?[^"]+)"`)

	sensorScriptPathExpr = regexp.MustCompile(`<script type="text/javascript"\s+(?:nonce=".*")?\s+src="((?i)[a-z\d/\-_]+)"></script>`)
	sbsdScriptPathExpr   = regexp.MustCompile(`(?is)\bsrc\s*=\s*["']([^"'\?]+)\?[^"']*?\bv=([^"'&]+)`)
)

func CreateAkamaiSession(apiKey string) *hyper.Session {
	return hyper.NewSession(apiKey)
}

func ParseScriptPathSensor(src []byte) (string, error) {
	matches := sensorScriptPathExpr.FindSubmatch(src)
	if len(matches) < 2 {
		return "", fmt.Errorf("script path not found")
	}

	blockLink := string(matches[1])
	blockLink = strings.ReplaceAll(blockLink, "&amp;", "&")

	return blockLink, nil
}

func ParseScriptPathSbsd(src []byte) (path string, v string, err error) {

	m := sbsdScriptPathExpr.FindSubmatch(src)
	if len(m) < 3 {
		return "", "", fmt.Errorf("script path not found")
	}

	path = strings.ReplaceAll(string(m[1]), "&amp;", "&")
	v = string(m[2])
	return path, v, nil
}

func GenerateSensorData(session *hyper.Session, input *hyper.SensorInput) (string, string, error) {
	sensorData, sensorContext, err := session.GenerateSensorData(context.Background(), input)
	if err != nil {
		return "", "", err
	}
	return sensorData, sensorContext, nil
}

func GenerateSbsdPayload(session *hyper.Session, input *hyper.SbsdInput) (string, error) {
	payload, err := session.GenerateSbsdData(context.Background(), input)
	if err != nil {
		return "", err
	}
	return payload, nil
}

func IsCookieValid(cookie string, requestCount int) bool {
	parts := strings.Split(cookie, "~")
	if len(parts) < 2 {
		return false
	}

	requestThreshold, err := strconv.Atoi(parts[1])
	if err != nil {
		requestThreshold = -1
	}
	fmt.Println("IsCookieValid requestThreshold", requestThreshold)

	return requestThreshold != -1 && requestCount >= requestThreshold
}

func IsCookieInvalidated(cookie string) bool {
	parts := strings.Split(cookie, "~")
	if len(parts) < 4 {
		return false
	}

	signal, err := strconv.Atoi(parts[3])
	if err != nil {
		signal = -1
	}
	fmt.Println("IsCookieInvalidated signal", signal)

	return signal > -1
}
