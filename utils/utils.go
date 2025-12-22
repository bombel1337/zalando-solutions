package utils

import (
	"encoding/csv"
	"fmt"
	"io"
	"math/rand/v2"
	"os"
	"strings"
	"time"
)

func readTasksCSV(filename string) ([]Data, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	r := csv.NewReader(f)

	headers, err := r.Read()
	if err != nil {
		return nil, err
	}

	setters := map[string]func(*Data, string){
		"Zalando_Email":    func(d *Data, v string) { d.ZalandoEmail = v },
		"Zalando_Password": func(d *Data, v string) { d.ZalandoPassword = v },
		"IS_Change_Email[y/n]": func(d *Data, v string) {
			v = strings.TrimSpace(strings.ToLower(v))
			d.ChangeEmail = (v == "y" || v == "yes" || v == "true" || v == "1")
		},
		"New_Email":        func(d *Data, v string) { d.NewZalandoEmail = v },
		"Interia_Email":    func(d *Data, v string) { d.InteriaEmail = v },
		"Interia_Password": func(d *Data, v string) { d.InteriaPassword = v },
	}

	// Resolve header -> setter by column index once
	colSetters := make([]func(*Data, string), len(headers))
	for i, h := range headers {
		h = strings.TrimSpace(h)
		if set, ok := setters[h]; ok {
			colSetters[i] = set
		} else {
			// Unknown header: warn but continue
			ColorfulLog(ColorRed, fmt.Sprintf("Unknown header column in task file: %q", h))
		}
	}

	var tasks []Data
	for {
		row, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		var d Data
		for i := 0; i < len(row) && i < len(colSetters); i++ {
			if colSetters[i] != nil {
				colSetters[i](&d, row[i])
			}
		}
		tasks = append(tasks, d)
	}

	return tasks, nil
}


func HumanDelay(minMs, maxMs int) {
	if minMs >= maxMs {
		time.Sleep(time.Duration(minMs) * time.Millisecond)
		return
	}
	delay := minMs + rand.IntN(maxMs-minMs)
	time.Sleep(time.Duration(delay) * time.Millisecond)
}
