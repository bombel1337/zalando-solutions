package zalando

import "zalando-solutions/utils"

type zalaTask struct {
	*utils.Task
}

func NewClient(t *utils.Task) *zalaTask {
	return &zalaTask{Task: t}
}
