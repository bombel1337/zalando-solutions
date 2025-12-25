package utils

import (
	"os"
	"sync"
	"time"

	"github.com/enetx/g"

	"zalando-solutions/akamai"

	"github.com/enetx/surf"

	"github.com/Hyper-Solutions/hyper-sdk-go/v2"
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
	Client         *surf.Client
	Data           Data
	DebugIP        string
	Delay          time.Duration
	ErrorDelay     time.Duration
	MaxRetries     int
	Akamai         Akamai
	ProxyList      []string
	FirstNames     []string
	LastNames      []string

	proxyMu      sync.RWMutex
	currentProxy string
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

func (t *Task) initSurfClientWithDynamicProxy() {
	t.Client = surf.NewClient().Builder().Session().Singleton().
		JA().
		Chrome142().ForceHTTP1().NotFollowRedirects().
		Proxy(func() g.String {
			t.proxyMu.RLock()
			p := t.currentProxy
			t.proxyMu.RUnlock()
			return g.String(p)
		}).
		Build()

	// Builder().
	// Session().
	// Singleton().
	// Impersonate().Chrome().
	// NotFollowRedirects().
	// Proxy(func() g.String {
	// 	t.proxyMu.RLock()
	// 	p := t.currentProxy
	// 	t.proxyMu.RUnlock()
	// 	return g.String(p)
	// }).
	// Build()
}

func ClientInit(cfg ClientConfig) (*[]*Task, error) {
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
		LogError(-1, "ClientInit", "Failed to load proxies", err)
		return nil, err
	}

	lastnames, err := loadProxies(cfg.LastNamesFile)
	if err != nil {
		LogError(-1, "ClientInit", "Failed to load proxies", err)
		return nil, err
	}

	firstnames, err := loadProxies(cfg.FirstNamesFile)
	if err != nil {
		LogError(-1, "ClientInit", "Failed to load proxies", err)
		return nil, err
	}

	tasks := make([]*Task, 0, len(records))

	for i, v := range records {
		task := &Task{
			CountryISOCode: "pl",
			TaskNumber:     i + 1,
			DebugIP:        cfg.DebugIP,
			ProxyList:      proxyList,
			Data:           v,
			Delay:          cfg.Delay,
			ErrorDelay:     cfg.ErrorDelay,
			MaxRetries:     cfg.MaxRetries,
			FirstNames:     firstnames,
			LastNames:      lastnames,
		}

		task.initSurfClientWithDynamicProxy()
		task.Akamai.AkamaiClient = akamai.CreateAkamaiSession(cfg.AkamaiApiKey)

		tasks = append(tasks, task)
	}

	return &tasks, nil
}
