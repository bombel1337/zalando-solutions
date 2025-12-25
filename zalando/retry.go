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
			return res, nil
		}

		he, ok := err.(HTTPError)
		if !ok {
			// do NOT log here -> caller logs once
			return res, err
		}

		if !retryable(he.Code) {
			// do NOT log here -> caller logs once
			return res, fmt.Errorf("%s failed (non-retryable): %w", name, err)
		}

		// only retry logging here
		utils.LogWarning(z.TaskNumber, name,
			fmt.Sprintf(`attempt %d/%d failed status=%d msg=%q`, i, max, he.Code, res.Msg),
		)

		if i < max {
			time.Sleep(z.ErrorDelay)
		}
	}

	// only one final log here (optional; otherwise let caller do it)
	utils.LogError(z.TaskNumber, name, fmt.Sprintf(`exhausted retries last_msg=%q`, lastRes.Msg), lastErr)
	return lastRes, fmt.Errorf("%s failed after %d retries: %w", name, max, lastErr)
}

