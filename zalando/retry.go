package zalando

import (
	"fmt"
	"zalando-solutions/utils"

	"time"
)

type HTTPError struct {
	Code int
	Msg  string
}

func (e HTTPError) Error() string {
	return fmt.Sprintf("http %d", e.Code)
}

func retryable(code int) bool {
	switch code {
	case 429, 500, 502, 503, 504:
		return true
	default:
		return false
	}
}
func (z *zalaTask) retryLogic(name string, fn func() (Result, error)) (Result, error) {
	max := z.MaxRetries
	if max <= 0 {
		max = 1
	}

	var lastRes Result
	var lastErr error

	for i := 1; i <= max; i++ {
		res, err := fn()
		lastRes, lastErr = res, err

		if err == nil {
			// utils.LogInfo(t.TaskNumber, name, fmt.Sprintf(`attempt %d/%d success msg=%q`, i, max, res.Msg))
			return res, nil
		}

		he, ok := err.(HTTPError)
		if !ok {
			utils.LogError(z.TaskNumber, name, fmt.Sprintf(`attempt %d/%d unexpected msg=%q`, i, max, res.Msg), err)
			return res, err
		}

		if !retryable(he.Code) {
			utils.LogError(z.TaskNumber, name,
				fmt.Sprintf(`non-retryable status=%d msg=%q`, he.Code, res.Msg),
				err,
			)
			return res, fmt.Errorf("%s failed (non-retryable): %w", name, err)
		} else {
			utils.LogWarning(z.TaskNumber, name,
				fmt.Sprintf(`attempt %d/%d failed status=%d msg=%q`, i, max, he.Code, res.Msg),
			)
		}

		if i < max {
			time.Sleep(z.ErrorDelay)
		}
	}

	utils.LogError(z.TaskNumber, name, fmt.Sprintf(`exhausted retries last_msg=%q`, lastRes.Msg), lastErr)
	return lastRes, fmt.Errorf("%s failed after %d retries: %w", name, max, lastErr)
}
