package api

import (
	"net/http"

	"github.com/cabernety/gopkg/httplib"
)

func (a *Api) GetUsers(w http.ResponseWriter, r *http.Request) {
	users, err := a.manager.GetUsers(httplib.ParsePageConfig(r))
	if err != nil {
		httplib.Resp(w, httplib.STATUS_INTERNAL_SERVER_ERR, nil, err.Error())
		return
	}
	var results []map[string]interface{}
	for _, user := range users {
		results = append(results, user.APIJson())
	}
	httplib.Resp(w, httplib.STATUS_OK, results)
}

func (a *Api) GetUser(w http.ResponseWriter, r *http.Request) {
	us := r.Context().Value("user")
	if us == nil {
		httplib.Resp(w, httplib.STATUS_NOT_FOUND, nil)
		return
	}
	ctx := us.(map[string]interface{})
	if ctx == nil || ctx["uid"] == nil {
		httplib.Resp(w, httplib.STATUS_NOT_FOUND, nil)
		return
	}
	id := ctx["uid"].(string)
	u := a.manager.GetUserById(id)
	if u == nil {
		httplib.Resp(w, httplib.STATUS_NOT_FOUND, nil, "not found")
		return
	}
	httplib.Resp(w, httplib.STATUS_OK, u.APIJson())
}
