package api

import (
	"fmt"
	"net/http"

	emailApi "github.com/BoxLinker/email/api"
	"github.com/BoxLinker/user/auth"
	userModels "github.com/BoxLinker/user/models"
	"golang.org/x/crypto/bcrypt"

	"encoding/json"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/cabernety/gopkg/httplib"
)

type (
	ChangePasswordForm struct {
		OldPassword     string `json:"old_password"`
		NewPassword     string `json:"new_password"`
		ConfirmPassword string `json:"confirm_password"`
	}
)

func (f *ChangePasswordForm) validate() map[string]int {
	m := make(map[string]int)
	if f.OldPassword == "" {
		m["old_password"] = httplib.STATUS_FIELD_REQUIRED
		return m
	}
	if f.NewPassword == "" {
		m["new_password"] = httplib.STATUS_FIELD_REQUIRED
		return m
	} else if len(f.NewPassword) < 6 {
		m["new_password"] = httplib.STATUS_FIELD_REGEX_FAILED
		return m
	}

	if f.NewPassword != f.ConfirmPassword {
		m["confirm_password"] = httplib.STATUS_PASSWORD_CONFIRM_FAILED
		return m
	}

	if f.NewPassword == f.OldPassword {
		m["new_password"] = httplib.STATUS_NEW_OLD_PASSWORD_SAME
		return m
	}

	if len(m) == 0 {
		return nil
	}
	return m
}

func (a *Api) ResetPassword(w http.ResponseWriter, r *http.Request) {
	form := &ChangePasswordForm{}

	u := a.getUserInfo(r)

	if err := httplib.ReadRequestBody(r, form); err != nil {
		httplib.Resp(w, httplib.STATUS_INTERNAL_SERVER_ERR, nil, err.Error())
		return
	}

	if form.NewPassword != form.ConfirmPassword {
		httplib.Resp(w, httplib.STATUS_FAILED, nil, "两次密码不一致")
		return
	}

	hash, err := auth.Hash(form.NewPassword)
	if err != nil {
		httplib.Resp(w, httplib.STATUS_INTERNAL_SERVER_ERR, nil, err.Error())
		return
	}

	// 验证原始密码有效性
	user, err := a.manager.GetUserByName(u.Name)
	if err != nil {
		httplib.Resp(w, httplib.STATUS_INTERNAL_SERVER_ERR, nil, err.Error())
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(form.OldPassword)); err != nil {
		httplib.Resp(w, httplib.STATUS_FAILED, nil, "原始密码不正确")
		return
	}

	if success, err := a.manager.UpdatePassword(u.Id, hash); err != nil {
		httplib.Resp(w, httplib.STATUS_INTERNAL_SERVER_ERR, nil, err.Error())
		return
	} else if !success {
		httplib.Resp(w, httplib.STATUS_FAILED, nil, "修改失败")
		return
	} else {
		httplib.Resp(w, httplib.STATUS_OK, nil, "修改成功")
	}

}

type SendForgotEmailForm struct {
	Email string `json:"email"`
}

func (a *Api) SendForgotEmail(w http.ResponseWriter, r *http.Request) {
	form := &SendForgotEmailForm{}
	if err := httplib.ReadRequestBody(r, form); err != nil {
		httplib.Resp(w, httplib.STATUS_INTERNAL_SERVER_ERR, nil, err.Error())
		return
	}
	var (
		user *userModels.User
		err  error
	)
	if user, _ = a.manager.GetUserByEmail(form.Email); user == nil {
		httplib.Resp(w, httplib.STATUS_NOT_FOUND, nil, "用户不存在")
		return
	}

	logrus.Debugf("GetUserByEmail %+v", user)

	token, err := a.manager.GenerateToken(user.Id, user.Name, time.Now().Add(time.Minute*15).Unix())

	if err != nil {
		httplib.Resp(w, httplib.STATUS_INTERNAL_SERVER_ERR, fmt.Errorf("generate token err: %v", err))
		return
	}
	eF := &emailApi.SendForm{
		To:      []string{form.Email},
		Subject: "用户忘记密码邮件 -- 无需回复",
		Body: fmt.Sprintf("<h3>点击下面的链接来修改密码(有效时间 15 分钟)：</h3><br/><a target=\"_blank\" href=\"%s\">%s</a>",
			fmt.Sprintf("%s?access_token=%s", a.config.ResetPassCallbackURI, token),
			"点击这里，修改密码",
		),
	}
	logrus.Debugf("send token auth email: %+v", eF)
	b, err := json.Marshal(eF)
	if err != nil {
		httplib.Resp(w, httplib.STATUS_INTERNAL_SERVER_ERR, fmt.Errorf("email form marshal err: %v", err))
		return
	}
	logrus.Debugf("send email to: %s", a.config.SendEmailUri)
	resp, err := httplib.Post(a.config.SendEmailUri).Body(b).Response()
	if err != nil {
		httplib.Resp(w, httplib.STATUS_INTERNAL_SERVER_ERR, nil, fmt.Sprintf("send email err: %v", err))
		return
	}
	status, msg, results, err := httplib.ParseResp(resp.Body)

	logrus.Debugf("send email results: %d, %s, %+v, %v", status, msg, results, err)

	if err != nil {
		httplib.Resp(w, httplib.STATUS_FAILED, nil, fmt.Sprintf("send email failed: (%s)", err.Error()))
		return
	}

	// 发送邮件失败，删除 userToBeConfirmed
	if status != httplib.STATUS_OK {
		httplib.Resp(w, httplib.STATUS_INTERNAL_SERVER_ERR, nil, fmt.Sprintf("send email failed: (%d)", status))
		return
	}
	httplib.Resp(w, httplib.STATUS_OK, nil)
}
func (a *Api) ChangePassword(w http.ResponseWriter, r *http.Request) {

	form := &ChangePasswordForm{}

	if err := httplib.ReadRequestBody(r, form); err != nil {
		httplib.Resp(w, httplib.STATUS_INTERNAL_SERVER_ERR, nil, err.Error())
		return
	}
	if validate := form.validate(); validate != nil {
		httplib.Resp(w, httplib.STATUS_FORM_VALIDATE_ERR, validate, "表单校验错误")
		return
	}
	ctx := r.Context().Value("user").(map[string]interface{})
	if ctx == nil || ctx["id"] == nil {
		httplib.Resp(w, httplib.STATUS_NOT_FOUND, nil)
		return
	}
	id := ctx["id"].(string)
	u := a.manager.GetUserById(id)
	if u == nil {
		httplib.Resp(w, httplib.STATUS_NOT_FOUND, nil, "not found")
		return
	}
	// 验证原始密码正确性
	if ok, err := a.manager.VerifyUsernamePassword(u.Name, form.OldPassword, u.Password); err != nil {
		httplib.Resp(w, httplib.STATUS_INTERNAL_SERVER_ERR, nil, err.Error())
		return
	} else if !ok {
		httplib.Resp(w, httplib.STATUS_OLD_PASSWORD_AUTH_FAILED, nil, "原始密码错误")
		return
	}

	if form.NewPassword != form.ConfirmPassword {
		httplib.Resp(w, httplib.STATUS_FAILED, "两次新密码不一致")
		return
	}

	hash, err := auth.Hash(form.NewPassword)
	if err != nil {
		httplib.Resp(w, httplib.STATUS_INTERNAL_SERVER_ERR, nil, err.Error())
		return
	}
	if success, err := a.manager.UpdatePassword(u.Id, hash); err != nil {
		httplib.Resp(w, httplib.STATUS_INTERNAL_SERVER_ERR, nil, err.Error())
		return
	} else if !success {
		httplib.Resp(w, httplib.STATUS_FAILED, nil, "修改失败")
		return
	} else {
		httplib.Resp(w, httplib.STATUS_OK, nil, "修改成功")
	}
}
