package api

import (
	"net/http"

	"github.com/Sirupsen/logrus"
	"github.com/cabernety/gopkg/httplib"
)

func (a *Api) AuthToken(w http.ResponseWriter, r *http.Request) {
	u := r.Context().Value("user")
	logrus.Debugf("AuthToken result: %+v", u)
	httplib.Resp(w, httplib.STATUS_OK, u)
}
