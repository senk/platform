// Copyright (c) 2017 Mattermost, Inc. All Rights Reserved.
// See License.txt for license information.

package api4

import (
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/mattermost/platform/app"
	"github.com/mattermost/platform/model"
	"github.com/mattermost/platform/utils"
)

func TestCreateUser(t *testing.T) {
	th := Setup()
	Client := th.Client

	user := model.User{Email: GenerateTestEmail(), Nickname: "Corey Hulen", Password: "hello1", Username: GenerateTestUsername(), Roles: model.ROLE_SYSTEM_ADMIN.Id + " " + model.ROLE_SYSTEM_USER.Id}

	ruser, resp := Client.CreateUser(&user)
	CheckNoError(t, resp)

	Client.Login(user.Email, user.Password)

	if ruser.Nickname != user.Nickname {
		t.Fatal("nickname didn't match")
	}

	if ruser.Roles != model.ROLE_SYSTEM_USER.Id {
		t.Fatal("did not clear roles")
	}

	CheckUserSanitization(t, ruser)

	_, resp = Client.CreateUser(ruser)
	CheckBadRequestStatus(t, resp)

	ruser.Id = ""
	ruser.Username = GenerateTestUsername()
	ruser.Password = "passwd1"
	_, resp = Client.CreateUser(ruser)
	CheckErrorMessage(t, resp, "store.sql_user.save.email_exists.app_error")
	CheckBadRequestStatus(t, resp)

	ruser.Email = GenerateTestEmail()
	ruser.Username = user.Username
	_, resp = Client.CreateUser(ruser)
	CheckErrorMessage(t, resp, "store.sql_user.save.username_exists.app_error")
	CheckBadRequestStatus(t, resp)

	ruser.Email = ""
	_, resp = Client.CreateUser(ruser)
	CheckErrorMessage(t, resp, "model.user.is_valid.email.app_error")
	CheckBadRequestStatus(t, resp)

	if r, err := Client.DoApiPost("/users", "garbage"); err == nil {
		t.Fatal("should have errored")
	} else {
		if r.StatusCode != http.StatusBadRequest {
			t.Log("actual: " + strconv.Itoa(r.StatusCode))
			t.Log("expected: " + strconv.Itoa(http.StatusBadRequest))
			t.Fatal("wrong status code")
		}
	}
}

func TestGetUser(t *testing.T) {
	th := Setup().InitBasic().InitSystemAdmin()
	Client := th.Client

	user := th.CreateUser()

	ruser, resp := Client.GetUser(user.Id, "")
	CheckNoError(t, resp)
	CheckUserSanitization(t, ruser)

	if ruser.Email != user.Email {
		t.Fatal("emails did not match")
	}

	ruser, resp = Client.GetUser(user.Id, resp.Etag)
	CheckEtag(t, ruser, resp)

	_, resp = Client.GetUser("junk", "")
	CheckBadRequestStatus(t, resp)

	_, resp = Client.GetUser(model.NewId(), "")
	CheckNotFoundStatus(t, resp)

	// Check against privacy config settings
	emailPrivacy := utils.Cfg.PrivacySettings.ShowEmailAddress
	namePrivacy := utils.Cfg.PrivacySettings.ShowFullName
	defer func() {
		utils.Cfg.PrivacySettings.ShowEmailAddress = emailPrivacy
		utils.Cfg.PrivacySettings.ShowFullName = namePrivacy
	}()
	utils.Cfg.PrivacySettings.ShowEmailAddress = false
	utils.Cfg.PrivacySettings.ShowFullName = false

	ruser, resp = Client.GetUser(user.Id, "")
	CheckNoError(t, resp)

	if ruser.Email != "" {
		t.Fatal("email should be blank")
	}
	if ruser.FirstName != "" {
		t.Fatal("first name should be blank")
	}
	if ruser.LastName != "" {
		t.Fatal("last name should be blank")
	}

	Client.Logout()
	_, resp = Client.GetUser(user.Id, "")
	CheckUnauthorizedStatus(t, resp)

	// System admins should ignore privacy settings
	ruser, resp = th.SystemAdminClient.GetUser(user.Id, resp.Etag)
	if ruser.Email == "" {
		t.Fatal("email should not be blank")
	}
	if ruser.FirstName == "" {
		t.Fatal("first name should not be blank")
	}
	if ruser.LastName == "" {
		t.Fatal("last name should not be blank")
	}
}

func TestUpdateUser(t *testing.T) {
	th := Setup().InitBasic().InitSystemAdmin()
	Client := th.Client

	user := th.CreateUser()
	Client.Login(user.Email, user.Password)

	user.Nickname = "Joram Wilander"
	user.Roles = model.ROLE_SYSTEM_ADMIN.Id
	user.LastPasswordUpdate = 123

	ruser, resp := Client.UpdateUser(user)
	CheckNoError(t, resp)
	CheckUserSanitization(t, ruser)

	if ruser.Nickname != "Joram Wilander" {
		t.Fatal("Nickname did not update properly")
	}
	if ruser.Roles != model.ROLE_SYSTEM_USER.Id {
		t.Fatal("Roles should not have updated")
	}
	if ruser.LastPasswordUpdate == 123 {
		t.Fatal("LastPasswordUpdate should not have updated")
	}

	ruser.Id = "junk"
	_, resp = Client.UpdateUser(ruser)
	CheckBadRequestStatus(t, resp)

	ruser.Id = model.NewId()
	_, resp = Client.UpdateUser(ruser)
	CheckForbiddenStatus(t, resp)

	if r, err := Client.DoApiPut("/users/"+ruser.Id, "garbage"); err == nil {
		t.Fatal("should have errored")
	} else {
		if r.StatusCode != http.StatusBadRequest {
			t.Log("actual: " + strconv.Itoa(r.StatusCode))
			t.Log("expected: " + strconv.Itoa(http.StatusBadRequest))
			t.Fatal("wrong status code")
		}
	}

	Client.Logout()
	_, resp = Client.UpdateUser(user)
	CheckUnauthorizedStatus(t, resp)

	th.LoginBasic()
	_, resp = Client.UpdateUser(user)
	CheckForbiddenStatus(t, resp)

	_, resp = th.SystemAdminClient.UpdateUser(user)
	CheckNoError(t, resp)
}

func TestResetPassword(t *testing.T) {
	th := Setup().InitBasic()
	Client := th.Client

	Client.Logout()

	user := th.BasicUser

	// Delete all the messages before check the reset password
	utils.DeleteMailBox(user.Email)

	success, resp := Client.SendPasswordResetEmail(user.Email)
	CheckNoError(t, resp)
	if !success {
		t.Fatal("should have succeeded")
	}

	_, resp = Client.SendPasswordResetEmail("")
	CheckBadRequestStatus(t, resp)

	// Should not leak whether the email is attached to an account or not
	success, resp = Client.SendPasswordResetEmail("notreal@example.com")
	CheckNoError(t, resp)
	if !success {
		t.Fatal("should have succeeded")
	}

	var recovery *model.PasswordRecovery
	if result := <-app.Srv.Store.PasswordRecovery().Get(user.Id); result.Err != nil {
		t.Fatal(result.Err)
	} else {
		recovery = result.Data.(*model.PasswordRecovery)
	}

	// Check if the email was send to the right email address and the recovery key match
	if resultsMailbox, err := utils.GetMailBox(user.Email); err != nil && !strings.ContainsAny(resultsMailbox[0].To[0], user.Email) {
		t.Fatal("Wrong To recipient")
	} else {
		if resultsEmail, err := utils.GetMessageFromMailbox(user.Email, resultsMailbox[0].ID); err == nil {
			if !strings.Contains(resultsEmail.Body.Text, recovery.Code) {
				t.Log(resultsEmail.Body.Text)
				t.Log(recovery.Code)
				t.Fatal("Received wrong recovery code")
			}
		}
	}

	_, resp = Client.ResetPassword(recovery.Code, "")
	CheckBadRequestStatus(t, resp)

	_, resp = Client.ResetPassword(recovery.Code, "newp")
	CheckBadRequestStatus(t, resp)

	_, resp = Client.ResetPassword("", "newpwd")
	CheckBadRequestStatus(t, resp)

	_, resp = Client.ResetPassword("junk", "newpwd")
	CheckBadRequestStatus(t, resp)

	code := ""
	for i := 0; i < model.PASSWORD_RECOVERY_CODE_SIZE; i++ {
		code += "a"
	}

	_, resp = Client.ResetPassword(code, "newpwd")
	CheckBadRequestStatus(t, resp)

	success, resp = Client.ResetPassword(recovery.Code, "newpwd")
	CheckNoError(t, resp)
	if !success {
		t.Fatal("should have succeeded")
	}

	Client.Login(user.Email, "newpwd")
	Client.Logout()

	_, resp = Client.ResetPassword(recovery.Code, "newpwd")
	CheckBadRequestStatus(t, resp)

	authData := model.NewId()
	if result := <-app.Srv.Store.User().UpdateAuthData(user.Id, "random", &authData, "", true); result.Err != nil {
		t.Fatal(result.Err)
	}

	_, resp = Client.SendPasswordResetEmail(user.Email)
	CheckBadRequestStatus(t, resp)
}
