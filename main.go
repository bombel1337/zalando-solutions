package main

import (
	"fmt"
	"os"
	"time"

	"zalando-solutions/utils"
	"zalando-solutions/zalando"

	"github.com/joho/godotenv"
)

const (
	logsDir = "logs"

	delay          = 1 * time.Second
	errorDelay     = 5 * time.Second
	maxRetries     = 3
	proxyFileName  = "proxies.txt"
	lastNamesFile  = "firstnames.txt"
	firstNamesFile = "lastnames.txt"
	tasksFileName  = "tasks.csv"

	debugIP = "http://127.0.0.1:55432" // http://127.0.0.1:8000
)

func main() {
	if err := utils.InitLogger(logsDir, false); err != nil {
		utils.ColorfulLog(utils.ColorRed, fmt.Sprintf("Failed to initialize logger: %v", err))
		return
	}
	err := godotenv.Load()
	if err != nil {
		utils.ColorfulLog(utils.ColorRed, fmt.Sprintf("Failed to load dotenv: %v", err))
		return
	}
	akamaiApiKey := os.Getenv("AKAMAI_API_KEY")
	if akamaiApiKey == "" {
		utils.ColorfulLog(utils.ColorRed, fmt.Sprintf("Failed to get akamai key"))
		return
	}
	utils.LogInfo(-1, "main", "Starting application")

	tasks, err := utils.ClientInit(utils.ClientConfig{
		TasksFile:      tasksFileName,
		ProxyFile:      proxyFileName,
		FirstNamesFile: firstNamesFile,
		LastNamesFile:  lastNamesFile,
		Delay:          delay,
		ErrorDelay:     errorDelay,
		DebugIP:        debugIP,
		MaxRetries:     3,
		AkamaiApiKey:   akamaiApiKey,
	})
	if err != nil {
		utils.LogError(-1, "main", "Failed to create client", err)
		return
	}
	for _, task := range *tasks {
		// fmt.Println(task.TaskNumber, task.Data.ZalandoEmail)
		zalando.ZalandoInit(task)
	}

	utils.LogInfo(-1, "main", "Successfully prepared app")
	time.Sleep(9999 * time.Hour)
}
