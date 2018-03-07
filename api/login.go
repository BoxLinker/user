package api

import (
	"fmt"
	"net/http"
	"time"

	settings "github.com/BoxLinker/user/settings"
	log "github.com/Sirupsen/logrus"
	"github.com/cabernety/gopkg/httplib"
	"golang.org/x/crypto/bcrypt"
)

type LoginForm struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (f *LoginForm) validate() string {
	if f.Username == "" {
		return "您还没有填写用户名"
	}
	if f.Password == "" {
		return "您还没有填写用户名"
	}
	return ""
}

func (a *Api) BasicAuth(w http.ResponseWriter, r *http.Request) {
	user, pass, ok := r.BasicAuth()
	if !ok {
		http.Error(w, "", http.StatusBadRequest)
		return
	}
	log.Debugf("user: %s, pass: %s", user, pass)
	u, err := a.manager.GetUserByName(user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if u == nil {
		log.Debugf("user %s not found", user)
		http.Error(w, "", http.StatusNotFound)
		return
	}
	log.Debugf("user found (%+v)", u)

	if err := bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(pass)); err != nil {
		http.Error(w, "", http.StatusUnauthorized)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok"))
}

func (a *Api) Login(w http.ResponseWriter, r *http.Request) {
	form := &LoginForm{}
	if err := httplib.ReadRequestBody(r, form); err != nil {
		httplib.Resp(w, httplib.STATUS_INTERNAL_SERVER_ERR, nil, err.Error())
		return
	}
	log.Debugf("form: %v", form)
	if msg := form.validate(); msg != "" {
		httplib.Resp(w, 1, nil, msg)
		return
	}

	u, err := a.manager.GetUserByName(form.Username)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if u == nil {
		httplib.Resp(w, httplib.STATUS_NOT_FOUND, nil, fmt.Sprintf("用户 %s 还没有注册", form.Username))
		return
	}
	success, err := a.manager.VerifyUsernamePassword(form.Username, form.Password, u.Password)
	if err != nil {
		httplib.Resp(w, httplib.STATUS_INTERNAL_SERVER_ERR, nil, err.Error())
		return
	}
	if !success {
		httplib.Resp(w, httplib.STATUS_FAILED, nil, "用户名或密码错误")
		return
	}
	token, err := a.manager.GenerateToken(u.Id, u.Name)
	if err != nil {
		httplib.Resp(w, 1, nil, fmt.Sprintf("token 错误: %v", err))
		return
	}
	cookie := &http.Cookie{
		Name:    "X-Access-Token",
		Value:   token,
		Expires: time.Now().Add(30 * 24 * time.Hour),
		Domain:  settings.COOKIE_DOMAIN,
	}
	http.SetCookie(w, cookie)
	httplib.Resp(w, 0, map[string]string{
		"X-Access-Token": token,
	})
}
