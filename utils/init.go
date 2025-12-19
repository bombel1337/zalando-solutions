package utils

import (
	"fmt"
	"os"
	"time"

	"github.com/bogdanfinn/fhttp/cookiejar"

	"zalando-solutions/akamai"

	"github.com/Hyper-Solutions/hyper-sdk-go/v2"
	tls_client "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
)

type Data struct {
	ZalandoEmail    string `csv:"Zalando_Email"`
	ZalandoPassword string `csv:"Zalando_Password"`
	ChangeEmail     bool   `csv:"IS_Change_Email[y/n]"`
	NewZalandoEmail string `csv:"New_Email"`
	InteriaEmail    string `csv:"Interia_Email"`
	InteriaPassword string `csv:"Interia_Password"`
	CsrfToken       string
}
type Task struct {
	CountryISOCode string
	TaskNumber     int
	Client         tls_client.HttpClient
	Data           Data
	DebugIP        string
	Delay          time.Duration
	ErrorDelay     time.Duration
	MaxRetries     int
	Akamai         Akamai
	ProxyList      []string
	FirstNames     []string
	LastNames      []string
}

type ClientConfig struct {
	TasksFile      string
	ProxyFile      string
	FirstNamesFile string
	LastNamesFile  string
	Delay          time.Duration
	ErrorDelay     time.Duration
	DebugIP        string
	MaxRetries     int
	AkamaiApiKey   string
}
type Akamai struct {
	AkamaiClient *hyper.Session
	IPAddress    string
	Sensor       sensor
	Sbsd         sbsd
	Pixel        pixel
	Domain       string
	Referer      string
}
type sensor struct {
	PageUrl            string
	SensorPath         string
	SensorScriptString string
	SensorScriptUrl    string
	SensorData         string
}
type pixel struct {
	PageUrl              string
	PixelScriptUrl       string
	PixelScriptString    string
	Bazadebezolkohpepadr string
	U                    string
}
type sbsd struct {
	PageUrl          string
	SbsdScriptUrl    string
	SbsdScriptString string
	SbsdPath         string
	SbsdV            string
}

func createTLSClient() (tls_client.HttpClient, error) {
	jar, _ := cookiejar.New(nil)
	// jar := tls_client.NewCookieJar()

	options := []tls_client.HttpClientOption{
		tls_client.WithTimeoutSeconds(30),
		tls_client.WithClientProfile(profiles.Chrome_133),
		tls_client.WithCookieJar(jar),
		tls_client.WithRandomTLSExtensionOrder(),
		tls_client.WithNotFollowRedirects(),
	}

	client, err := tls_client.NewHttpClient(tls_client.NewLogger(), options...)
	if err != nil {
		return client, err
	}
	return client, nil
}
func ClientInit(cfg ClientConfig) (*[]Task, error) {
	if _, err := os.Stat(cfg.TasksFile); err != nil {
		return nil, err
	}
	if _, err := os.Stat(cfg.ProxyFile); err != nil {
		return nil, err
	}

	records, err := readTasksCSV(cfg.TasksFile)
	if err != nil {
		return nil, err
	}

	proxyList, err := loadProxies(cfg.ProxyFile)
	if err != nil {
		LogError(0, "ClientInit", "Failed to load proxies", err)
		return nil, err
	}

	lastnames, err := loadProxies(cfg.LastNamesFile)
	if err != nil {
		LogError(0, "ClientInit", "Failed to load proxies", err)
		return nil, err
	}

	firstnames, err := loadProxies(cfg.FirstNamesFile)
	if err != nil {
		LogError(0, "ClientInit", "Failed to load proxies", err)
		return nil, err
	}

	tasks := make([]Task, 0, len(records))

	for i, v := range records {
		client, err := createTLSClient()
		if err != nil {
			ColorfulLog(ColorRed, fmt.Sprintf("ClientInit - createTLSClient error - %s", err.Error()))
			return nil, err
		}
		task := Task{
			CountryISOCode: "pl",
			TaskNumber:     i + 1,
			Client:         client,
			DebugIP:        cfg.DebugIP,
			ProxyList:      proxyList,
			Data:           v,
			Delay:          cfg.Delay,
			ErrorDelay:     cfg.ErrorDelay,
			MaxRetries:     cfg.MaxRetries,
			FirstNames:     firstnames,
			LastNames:      lastnames,
		}
		task.Akamai.AkamaiClient = akamai.CreateAkamaiSession(cfg.AkamaiApiKey)
		tasks = append(tasks, task)
	}

	return &tasks, nil
}
