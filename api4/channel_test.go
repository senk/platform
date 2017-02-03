// Copyright (c) 2017 Mattermost, Inc. All Rights Reserved.
// See License.txt for license information.

package api4

import (
	"net/http"
	"strconv"
	"testing"

	"github.com/mattermost/platform/model"
	"github.com/mattermost/platform/utils"
)

func TestCreateChannel(t *testing.T) {
	th := Setup().InitBasic().InitSystemAdmin()
	Client := th.Client
	team := th.BasicTeam

	channel := &model.Channel{DisplayName: "Test API Name", Name: GenerateTestChannelName(), Type: model.CHANNEL_OPEN, TeamId: team.Id}
	private := &model.Channel{DisplayName: "Test API Name", Name: GenerateTestChannelName(), Type: model.CHANNEL_PRIVATE, TeamId: team.Id}

	rchannel, resp := Client.CreateChannel(channel)
	CheckNoError(t, resp)

	if rchannel.Name != channel.Name {
		t.Fatal("names did not match")
	}

	if rchannel.DisplayName != channel.DisplayName {
		t.Fatal("display names did not match")
	}

	if rchannel.TeamId != channel.TeamId {
		t.Fatal("team ids did not match")
	}

	rprivate, resp := Client.CreateChannel(private)
	CheckNoError(t, resp)

	if rprivate.Name != private.Name {
		t.Fatal("names did not match")
	}

	if rprivate.Type != model.CHANNEL_PRIVATE {
		t.Fatal("wrong channel type")
	}

	if rprivate.CreatorId != th.BasicUser.Id {
		t.Fatal("wrong creator id")
	}

	_, resp = Client.CreateChannel(channel)
	CheckErrorMessage(t, resp, "store.sql_channel.save_channel.exists.app_error")
	CheckBadRequestStatus(t, resp)

	direct := &model.Channel{DisplayName: "Test API Name", Name: GenerateTestChannelName(), Type: model.CHANNEL_DIRECT, TeamId: team.Id}
	_, resp = Client.CreateChannel(direct)
	CheckErrorMessage(t, resp, "api.channel.create_channel.direct_channel.app_error")
	CheckBadRequestStatus(t, resp)

	Client.Logout()
	_, resp = Client.CreateChannel(channel)
	CheckUnauthorizedStatus(t, resp)

	userNotOnTeam := th.CreateUser()
	Client.Login(userNotOnTeam.Email, userNotOnTeam.Password)

	_, resp = Client.CreateChannel(channel)
	CheckForbiddenStatus(t, resp)

	_, resp = Client.CreateChannel(private)
	CheckForbiddenStatus(t, resp)

	th.LoginBasic()

	// Check permissions with policy config changes
	isLicensed := utils.IsLicensed
	license := utils.License
	restrictPublicChannel := *utils.Cfg.TeamSettings.RestrictPublicChannelCreation
	restrictPrivateChannel := *utils.Cfg.TeamSettings.RestrictPrivateChannelCreation
	defer func() {
		*utils.Cfg.TeamSettings.RestrictPublicChannelCreation = restrictPublicChannel
		*utils.Cfg.TeamSettings.RestrictPrivateChannelCreation = restrictPrivateChannel
		utils.IsLicensed = isLicensed
		utils.License = license
		utils.SetDefaultRolesBasedOnConfig()
	}()
	*utils.Cfg.TeamSettings.RestrictPublicChannelCreation = model.PERMISSIONS_ALL
	*utils.Cfg.TeamSettings.RestrictPrivateChannelCreation = model.PERMISSIONS_ALL
	utils.SetDefaultRolesBasedOnConfig()
	utils.IsLicensed = true
	utils.License = &model.License{Features: &model.Features{}}
	utils.License.Features.SetDefaults()

	channel.Name = GenerateTestChannelName()
	_, resp = Client.CreateChannel(channel)
	CheckNoError(t, resp)

	private.Name = GenerateTestChannelName()
	_, resp = Client.CreateChannel(private)
	CheckNoError(t, resp)

	*utils.Cfg.TeamSettings.RestrictPublicChannelCreation = model.PERMISSIONS_TEAM_ADMIN
	*utils.Cfg.TeamSettings.RestrictPrivateChannelCreation = model.PERMISSIONS_TEAM_ADMIN
	utils.SetDefaultRolesBasedOnConfig()

	_, resp = Client.CreateChannel(channel)
	CheckForbiddenStatus(t, resp)

	_, resp = Client.CreateChannel(private)
	CheckForbiddenStatus(t, resp)

	th.LoginTeamAdmin()

	channel.Name = GenerateTestChannelName()
	_, resp = Client.CreateChannel(channel)
	CheckNoError(t, resp)

	private.Name = GenerateTestChannelName()
	_, resp = Client.CreateChannel(private)
	CheckNoError(t, resp)

	channel.Name = GenerateTestChannelName()
	_, resp = th.SystemAdminClient.CreateChannel(channel)
	CheckNoError(t, resp)

	private.Name = GenerateTestChannelName()
	_, resp = th.SystemAdminClient.CreateChannel(private)
	CheckNoError(t, resp)

	*utils.Cfg.TeamSettings.RestrictPublicChannelCreation = model.PERMISSIONS_SYSTEM_ADMIN
	*utils.Cfg.TeamSettings.RestrictPrivateChannelCreation = model.PERMISSIONS_SYSTEM_ADMIN
	utils.SetDefaultRolesBasedOnConfig()

	th.LoginBasic()

	_, resp = Client.CreateChannel(channel)
	CheckForbiddenStatus(t, resp)

	_, resp = Client.CreateChannel(private)
	CheckForbiddenStatus(t, resp)

	th.LoginTeamAdmin()

	_, resp = Client.CreateChannel(channel)
	CheckForbiddenStatus(t, resp)

	_, resp = Client.CreateChannel(private)
	CheckForbiddenStatus(t, resp)

	channel.Name = GenerateTestChannelName()
	_, resp = th.SystemAdminClient.CreateChannel(channel)
	CheckNoError(t, resp)

	private.Name = GenerateTestChannelName()
	_, resp = th.SystemAdminClient.CreateChannel(private)
	CheckNoError(t, resp)

	if r, err := Client.DoApiPost("/channels", "garbage"); err == nil {
		t.Fatal("should have errored")
	} else {
		if r.StatusCode != http.StatusBadRequest {
			t.Log("actual: " + strconv.Itoa(r.StatusCode))
			t.Log("expected: " + strconv.Itoa(http.StatusBadRequest))
			t.Fatal("wrong status code")
		}
	}
}

func TestCreateDirectChannel(t *testing.T) {
	th := Setup().InitBasic().InitSystemAdmin()
	defer TearDown()
	Client := th.Client
	user1 := th.BasicUser
	user2 := th.BasicUser2
	user3 := th.CreateUser()

	dm, resp := Client.CreateDirectChannel(user1.Id, user2.Id)
	CheckNoError(t, resp)

	channelName := ""
	if user2.Id > user1.Id {
		channelName = user1.Id + "__" + user2.Id
	} else {
		channelName = user2.Id + "__" + user1.Id
	}

	if dm.Name != channelName {
		t.Fatal("dm name didn't match")
	}

	_, resp = Client.CreateDirectChannel("junk", user2.Id)
	CheckBadRequestStatus(t, resp)

	_, resp = Client.CreateDirectChannel(user1.Id, model.NewId())
	CheckBadRequestStatus(t, resp)

	_, resp = Client.CreateDirectChannel(model.NewId(), user1.Id)
	CheckBadRequestStatus(t, resp)

	_, resp = Client.CreateDirectChannel(model.NewId(), user2.Id)
	CheckForbiddenStatus(t, resp)

	if r, err := Client.DoApiPost("/channels/direct", "garbage"); err == nil {
		t.Fatal("should have errored")
	} else {
		if r.StatusCode != http.StatusBadRequest {
			t.Log("actual: " + strconv.Itoa(r.StatusCode))
			t.Log("expected: " + strconv.Itoa(http.StatusBadRequest))
			t.Fatal("wrong status code")
		}
	}

	Client.Logout()
	_, resp = Client.CreateDirectChannel(model.NewId(), user2.Id)
	CheckUnauthorizedStatus(t, resp)

	_, resp = th.SystemAdminClient.CreateDirectChannel(user3.Id, user2.Id)
	CheckNoError(t, resp)
}
