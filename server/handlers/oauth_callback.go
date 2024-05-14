package handlers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2"

	"github.com/authorizerdev/authorizer/server/constants"
	"github.com/authorizerdev/authorizer/server/cookie"
	"github.com/authorizerdev/authorizer/server/db"
	"github.com/authorizerdev/authorizer/server/db/models"
	"github.com/authorizerdev/authorizer/server/memorystore"
	"github.com/authorizerdev/authorizer/server/oauth"
	"github.com/authorizerdev/authorizer/server/token"
	"github.com/authorizerdev/authorizer/server/utils"
)

type TokenJSON struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
}

// OAuthCallbackHandler handles the OAuth callback for various oauth providers
func OAuthCallbackHandler() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		provider := ctx.Param("oauth_provider")
		state := ctx.Request.FormValue("state")

		sessionState, err := memorystore.Provider.GetState(state)
		if sessionState == "" || err != nil {
			log.Debug("Invalid oauth state: ", state)
			ctx.JSON(400, gin.H{"error": "invalid oauth state"})
		}
		// contains random token, redirect url, role
		sessionSplit := strings.Split(state, "___")

		if len(sessionSplit) < 3 {
			log.Debug("Unable to get redirect url from state: ", state)
			ctx.JSON(400, gin.H{"error": "invalid redirect url"})
			return
		}

		// remove state from store
		go memorystore.Provider.RemoveState(state)

		stateValue := sessionSplit[0]
		redirectURL := sessionSplit[1]
		inputRoles := strings.Split(sessionSplit[2], ",")
		scopes := strings.Split(sessionSplit[3], ",")

		user := models.User{}
		oauthCode := ctx.Request.FormValue("code")
		switch provider {
		case constants.AuthRecipeMethodZalo:
			user, err = processZaloUserInfo(oauthCode)
		case constants.AuthRecipeMethodGoogle:
			user, err = processGoogleUserInfo(oauthCode)
		case constants.AuthRecipeMethodGithub:
			user, err = processGithubUserInfo(oauthCode)
		case constants.AuthRecipeMethodFacebook:
			user, err = processFacebookUserInfo(oauthCode)
		case constants.AuthRecipeMethodLinkedIn:
			user, err = processLinkedInUserInfo(oauthCode)
		case constants.AuthRecipeMethodApple:
			user, err = processAppleUserInfo(oauthCode)
		case constants.AuthRecipeMethodTwitter:
			user, err = processTwitterUserInfo(oauthCode, sessionState)
		case constants.AuthRecipeMethodMicrosoft:
			user, err = processMicrosoftUserInfo(oauthCode)
		default:
			log.Info("Invalid oauth provider")
			err = fmt.Errorf(`invalid oauth provider`)
		}

		if err != nil {
			log.Debug("Failed to process user info: ", err)
			ctx.JSON(400, gin.H{"error": err.Error()})
			return
		}

		isSignUp := false

		// check oauth user has email
		log.Debug("User Email: ", user.Email)
		if user.Email == "<nil>" || user.Email == "" {

			existingUser := models.User{}
			// if does not have email => create a new user without email
			if provider == constants.AuthRecipeMethodFacebook {
				log.Debug("fb id: ", user.FbId)
				existingUser, err = db.Provider.GetUserByFbId(ctx, user.FbId)
			}

			if provider == constants.AuthRecipeMethodZalo {
				log.Debug("zalo id: ", user.ZaloId)
				existingUser, err = db.Provider.GetUserByZaloId(ctx, user.ZaloId)
			}

			if err != nil {
				log.Debug("query existing user err: ", err)
				log.Debug("register user: ", provider)
				user, err = insertUser(ctx, provider, user, inputRoles)
				if err != nil {
					log.Debug("Failed to register user: ", err)
					ctx.JSON(400, gin.H{"error": err.Error()})
					return
				}
				isSignUp = true
			} else {
				user = existingUser
				log.Debug("find user ok")
				log.Debug("userId: ", existingUser.ID)
			}

		} else {
			log.Debug("find verified email record")

			// else find verified email record
			existingUser, err := db.Provider.GetVerifiedUserByEmail(ctx, user.Email)
			if err != nil {

				log.Debug("delete all unverify email record on db and insert new one with verified email")
				// delete all unverify email record on db and insert new one with verified email
				err = db.Provider.DeleteUnverifyEmailUsers(ctx, user.Email)
				if err != nil {
					log.Debug("Failed to delete unverify user: ", err)
					ctx.JSON(500, gin.H{"error": err.Error()})
					return
				}

				user, err = insertUser(ctx, provider, user, inputRoles)
				if err != nil {
					log.Debug("Failed to register user: ", err)
					ctx.JSON(500, gin.H{"error": err.Error()})
					return
				}
				isSignUp = true
			} else {
				log.Debug("update existing user")
				// update existing user
				user, err = updateUser(ctx, provider, existingUser, inputRoles)
				if err != nil {
					log.Debug("Failed to register user: ", err)
					ctx.JSON(500, gin.H{"error": err.Error()})
					return
				}
			}
		}

		// TODO
		// use stateValue to get code / nonce
		// add code / nonce to id_token
		code := ""
		codeChallenge := ""
		nonce := ""
		if stateValue != "" {
			// Get state from store
			authorizeState, _ := memorystore.Provider.GetState(stateValue)
			if authorizeState != "" {
				authorizeStateSplit := strings.Split(authorizeState, "@@")
				if len(authorizeStateSplit) > 1 {
					code = authorizeStateSplit[0]
					codeChallenge = authorizeStateSplit[1]
				} else {
					nonce = authorizeState
				}
				go memorystore.Provider.RemoveState(stateValue)
			}
		}
		if nonce == "" {
			nonce = uuid.New().String()
		}
		authToken, err := token.CreateAuthToken(ctx, user, inputRoles, scopes, provider, nonce, code)
		if err != nil {
			log.Debug("Failed to create auth token: ", err)
			ctx.JSON(500, gin.H{"error": err.Error()})
		}

		// Code challenge could be optional if PKCE flow is not used
		if code != "" {
			if err := memorystore.Provider.SetState(code, codeChallenge+"@@"+authToken.FingerPrintHash); err != nil {
				log.Debug("SetState failed: ", err)
				ctx.JSON(500, gin.H{"error": err.Error()})
			}
		}

		expiresIn := authToken.AccessToken.ExpiresAt - time.Now().Unix()
		if expiresIn <= 0 {
			expiresIn = 1
		}

		params := "access_token=" + authToken.AccessToken.Token + "&token_type=bearer&expires_in=" + strconv.FormatInt(expiresIn, 10) + "&state=" + stateValue + "&id_token=" + authToken.IDToken.Token + "&nonce=" + nonce

		if code != "" {
			params += "&code=" + code
		}

		sessionKey := provider + ":" + user.ID
		cookie.SetSession(ctx, authToken.FingerPrintHash)
		memorystore.Provider.SetUserSession(sessionKey, constants.TokenTypeSessionToken+"_"+authToken.FingerPrint, authToken.FingerPrintHash, authToken.SessionTokenExpiresAt)
		memorystore.Provider.SetUserSession(sessionKey, constants.TokenTypeAccessToken+"_"+authToken.FingerPrint, authToken.AccessToken.Token, authToken.AccessToken.ExpiresAt)

		if authToken.RefreshToken != nil {
			params += `&refresh_token=` + authToken.RefreshToken.Token
			memorystore.Provider.SetUserSession(sessionKey, constants.TokenTypeRefreshToken+"_"+authToken.FingerPrint, authToken.RefreshToken.Token, authToken.RefreshToken.ExpiresAt)
		}

		go func() {
			if isSignUp {
				utils.RegisterEvent(ctx, constants.UserSignUpWebhookEvent, provider, user)
			} else {
				utils.RegisterEvent(ctx, constants.UserLoginWebhookEvent, provider, user)
			}
			db.Provider.AddSession(ctx, models.Session{
				UserID:    user.ID,
				UserAgent: utils.GetUserAgent(ctx.Request),
				IP:        utils.GetIP(ctx.Request),
			})
		}()
		if strings.Contains(redirectURL, "?") {
			redirectURL = redirectURL + "&" + params
		} else {
			redirectURL = redirectURL + "?" + strings.TrimPrefix(params, "&")
		}

		ctx.Redirect(http.StatusFound, redirectURL)
	}
}

func processZaloUserInfo(code string) (models.User, error) {
	user := models.User{}
	client := http.Client{}

	// get access_token
	reqBody := url.Values{}
	reqBody.Set("code", code)
	reqBody.Set("app_id", oauth.OAuthProviders.ZaloConfig.ClientID)
	reqBody.Set("grant_type", "authorization_code")

	reqAccessToken, err := http.NewRequest("POST", oauth.OAuthProviders.ZaloConfig.Endpoint.TokenURL, strings.NewReader(reqBody.Encode()))
	if err != nil {
		log.Debug("error creating post request: ", err)
		return user, err
	}
	reqAccessToken.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqAccessToken.Header.Set("secret_key", oauth.OAuthProviders.ZaloConfig.ClientSecret)
	accessTokenResp, err := client.Do(reqAccessToken)
	if err != nil {
		log.Debug("error making request: ", err)
		return user, err
	}
	defer accessTokenResp.Body.Close()

	accessTokenBody, err := ioutil.ReadAll(accessTokenResp.Body)
	if err != nil {
		log.Debug("error reading response: ", err)
		return user, err
	}

	var tj TokenJSON
	if err = json.Unmarshal(accessTokenBody, &tj); err != nil {
		return user, err
	}

	req, err := http.NewRequest("GET", constants.ZaloUserInfoURL, nil)
	if err != nil {
		log.Debug("Error creating zalo user info request: ", err)
		return user, fmt.Errorf("error creating zalo user info request: %s", err.Error())
	}

	req.Header.Set(
		"access_token", tj.AccessToken,
	)

	response, err := client.Do(req)
	if err != nil {
		log.Debug("Failed to process zalo user: ", err)
		return user, err
	}

	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		log.Debug("Failed to read zalo response: ", err)
		return user, fmt.Errorf("failed to read zalo response body: %s", err.Error())
	}
	if response.StatusCode >= 400 {
		log.Debug("Failed to request zalo user info: ", string(body))
		return user, fmt.Errorf("failed to request zalo user info: %s", string(body))
	}

	userRawData := make(map[string]interface{})
	json.Unmarshal(body, &userRawData)

	picObject := userRawData["picture"].(map[string]interface{})["data"]
	picDataObject := picObject.(map[string]interface{})
	name := fmt.Sprintf("%v", userRawData["name"])
	picture := fmt.Sprintf("%v", picDataObject["url"])
	zaloId := fmt.Sprintf("%v", userRawData["id"])

	user = models.User{
		GivenName: &name,
		Picture:   &picture,
		ZaloId:    zaloId,
	}

	return user, nil
}

func processGoogleUserInfo(code string) (models.User, error) {
	user := models.User{}
	ctx := context.Background()
	oauth2Token, err := oauth.OAuthProviders.GoogleConfig.Exchange(ctx, code)
	if err != nil {
		log.Debug("Failed to exchange code for token: ", err)
		return user, fmt.Errorf("invalid google exchange code: %s", err.Error())
	}

	verifier := oauth.OIDCProviders.GoogleOIDC.Verifier(&oidc.Config{ClientID: oauth.OAuthProviders.GoogleConfig.ClientID})

	// Extract the ID Token from OAuth2 token.
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		log.Debug("Failed to extract ID Token from OAuth2 token")
		return user, fmt.Errorf("unable to extract id_token")
	}

	// Parse and verify ID Token payload.
	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		log.Debug("Failed to verify ID Token: ", err)
		return user, fmt.Errorf("unable to verify id_token: %s", err.Error())
	}

	if err := idToken.Claims(&user); err != nil {
		log.Debug("Failed to parse ID Token claims: ", err)
		return user, fmt.Errorf("unable to extract claims")
	}

	qualityPicture := strings.ReplaceAll(*user.Picture, "s96-c", "s384-c")
	user.Picture = &qualityPicture

	return user, nil
}

func processGithubUserInfo(code string) (models.User, error) {
	user := models.User{}
	oauth2Token, err := oauth.OAuthProviders.GithubConfig.Exchange(context.TODO(), code)
	if err != nil {
		log.Debug("Failed to exchange code for token: ", err)
		return user, fmt.Errorf("invalid github exchange code: %s", err.Error())
	}
	client := http.Client{}
	req, err := http.NewRequest("GET", constants.GithubUserInfoURL, nil)
	if err != nil {
		log.Debug("Failed to create github user info request: ", err)
		return user, fmt.Errorf("error creating github user info request: %s", err.Error())
	}
	req.Header.Set(
		"Authorization", fmt.Sprintf("token %s", oauth2Token.AccessToken),
	)

	response, err := client.Do(req)
	if err != nil {
		log.Debug("Failed to request github user info: ", err)
		return user, err
	}

	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		log.Debug("Failed to read github user info response body: ", err)
		return user, fmt.Errorf("failed to read github response body: %s", err.Error())
	}
	if response.StatusCode >= 400 {
		log.Debug("Failed to request github user info: ", string(body))
		return user, fmt.Errorf("failed to request github user info: %s", string(body))
	}

	userRawData := make(map[string]string)
	json.Unmarshal(body, &userRawData)

	name := strings.Split(userRawData["name"], " ")
	firstName := ""
	lastName := ""
	if len(name) >= 1 && strings.TrimSpace(name[0]) != "" {
		firstName = name[0]
	}
	if len(name) > 1 && strings.TrimSpace(name[1]) != "" {
		lastName = name[0]
	}

	picture := userRawData["avatar_url"]
	email := userRawData["email"]

	if email == "" {
		type GithubUserEmails struct {
			Email   string `json:"email"`
			Primary bool   `json:"primary"`
		}

		// fetch using /users/email endpoint
		req, err := http.NewRequest(http.MethodGet, constants.GithubUserEmails, nil)
		if err != nil {
			log.Debug("Failed to create github emails request: ", err)
			return user, fmt.Errorf("error creating github user info request: %s", err.Error())
		}
		req.Header.Set(
			"Authorization", fmt.Sprintf("token %s", oauth2Token.AccessToken),
		)

		response, err := client.Do(req)
		if err != nil {
			log.Debug("Failed to request github user email: ", err)
			return user, err
		}

		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		if err != nil {
			log.Debug("Failed to read github user email response body: ", err)
			return user, fmt.Errorf("failed to read github response body: %s", err.Error())
		}
		if response.StatusCode >= 400 {
			log.Debug("Failed to request github user email: ", string(body))
			return user, fmt.Errorf("failed to request github user info: %s", string(body))
		}

		emailData := []GithubUserEmails{}
		err = json.Unmarshal(body, &emailData)
		if err != nil {
			log.Debug("Failed to parse github user email: ", err)
		}

		for _, userEmail := range emailData {
			email = userEmail.Email
			if userEmail.Primary {
				break
			}
		}
	}

	user = models.User{
		GivenName:  &firstName,
		FamilyName: &lastName,
		Picture:    &picture,
		Email:      email,
	}

	return user, nil
}

func processFacebookUserInfo(code string) (models.User, error) {
	user := models.User{}
	oauth2Token, err := oauth.OAuthProviders.FacebookConfig.Exchange(context.TODO(), code)
	if err != nil {
		log.Debug("Invalid facebook exchange code: ", err)
		return user, fmt.Errorf("invalid facebook exchange code: %s", err.Error())
	}
	client := http.Client{}
	req, err := http.NewRequest("GET", constants.FacebookUserInfoURL+oauth2Token.AccessToken, nil)
	if err != nil {
		log.Debug("Error creating facebook user info request: ", err)
		return user, fmt.Errorf("error creating facebook user info request: %s", err.Error())
	}

	response, err := client.Do(req)
	if err != nil {
		log.Debug("Failed to process facebook user: ", err)
		return user, err
	}

	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		log.Debug("Failed to read facebook response: ", err)
		return user, fmt.Errorf("failed to read facebook response body: %s", err.Error())
	}
	if response.StatusCode >= 400 {
		log.Debug("Failed to request facebook user info: ", string(body))
		return user, fmt.Errorf("failed to request facebook user info: %s", string(body))
	}
	userRawData := make(map[string]interface{})
	json.Unmarshal(body, &userRawData)

	email := fmt.Sprintf("%v", userRawData["email"])

	picObject := userRawData["picture"].(map[string]interface{})["data"]
	picDataObject := picObject.(map[string]interface{})
	firstName := fmt.Sprintf("%v", userRawData["first_name"])
	lastName := fmt.Sprintf("%v", userRawData["last_name"])
	picture := fmt.Sprintf("%v", picDataObject["url"])
	fbId := fmt.Sprintf("%v", userRawData["id"])

	user = models.User{
		GivenName:  &firstName,
		FamilyName: &lastName,
		Picture:    &picture,
		Email:      email,
		FbId:       fbId,
	}

	return user, nil
}

func processLinkedInUserInfo(code string) (models.User, error) {
	user := models.User{}
	oauth2Token, err := oauth.OAuthProviders.LinkedInConfig.Exchange(context.TODO(), code)
	if err != nil {
		log.Debug("Failed to exchange code for token: ", err)
		return user, fmt.Errorf("invalid linkedin exchange code: %s", err.Error())
	}

	client := http.Client{}
	req, err := http.NewRequest("GET", constants.LinkedInUserInfoURL, nil)
	if err != nil {
		log.Debug("Failed to create linkedin user info request: ", err)
		return user, fmt.Errorf("error creating linkedin user info request: %s", err.Error())
	}
	req.Header = http.Header{
		"Authorization": []string{fmt.Sprintf("Bearer %s", oauth2Token.AccessToken)},
	}

	response, err := client.Do(req)
	if err != nil {
		log.Debug("Failed to request linkedin user info: ", err)
		return user, err
	}

	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		log.Debug("Failed to read linkedin user info response body: ", err)
		return user, fmt.Errorf("failed to read linkedin response body: %s", err.Error())
	}

	if response.StatusCode >= 400 {
		log.Debug("Failed to request linkedin user info: ", string(body))
		return user, fmt.Errorf("failed to request linkedin user info: %s", string(body))
	}

	userRawData := make(map[string]interface{})
	json.Unmarshal(body, &userRawData)

	req, err = http.NewRequest("GET", constants.LinkedInEmailURL, nil)
	if err != nil {
		log.Debug("Failed to create linkedin email info request: ", err)
		return user, fmt.Errorf("error creating linkedin user info request: %s", err.Error())
	}
	req.Header = http.Header{
		"Authorization": []string{fmt.Sprintf("Bearer %s", oauth2Token.AccessToken)},
	}

	response, err = client.Do(req)
	if err != nil {
		log.Debug("Failed to request linkedin email info: ", err)
		return user, err
	}

	defer response.Body.Close()
	body, err = io.ReadAll(response.Body)
	if err != nil {
		log.Debug("Failed to read linkedin email info response body: ", err)
		return user, fmt.Errorf("failed to read linkedin email response body: %s", err.Error())
	}
	if response.StatusCode >= 400 {
		log.Debug("Failed to request linkedin user info: ", string(body))
		return user, fmt.Errorf("failed to request linkedin user info: %s", string(body))
	}
	emailRawData := make(map[string]interface{})
	json.Unmarshal(body, &emailRawData)

	firstName := userRawData["localizedFirstName"].(string)
	lastName := userRawData["localizedLastName"].(string)
	profilePicture := userRawData["profilePicture"].(map[string]interface{})["displayImage~"].(map[string]interface{})["elements"].([]interface{})[0].(map[string]interface{})["identifiers"].([]interface{})[0].(map[string]interface{})["identifier"].(string)
	emailAddress := emailRawData["elements"].([]interface{})[0].(map[string]interface{})["handle~"].(map[string]interface{})["emailAddress"].(string)

	user = models.User{
		GivenName:  &firstName,
		FamilyName: &lastName,
		Picture:    &profilePicture,
		Email:      emailAddress,
	}

	return user, nil
}

func processAppleUserInfo(code string) (models.User, error) {
	user := models.User{}
	oauth2Token, err := oauth.OAuthProviders.AppleConfig.Exchange(context.TODO(), code)
	if err != nil {
		log.Debug("Failed to exchange code for token: ", err)
		return user, fmt.Errorf("invalid apple exchange code: %s", err.Error())
	}

	// Extract the ID Token from OAuth2 token.
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		log.Debug("Failed to extract ID Token from OAuth2 token")
		return user, fmt.Errorf("unable to extract id_token")
	}

	tokenSplit := strings.Split(rawIDToken, ".")
	claimsData := tokenSplit[1]
	decodedClaimsData, err := base64.RawURLEncoding.DecodeString(claimsData)
	if err != nil {
		log.Debugf("Failed to decrypt claims %s: %s", claimsData, err.Error())
		return user, fmt.Errorf("failed to decrypt claims data: %s", err.Error())
	}

	claims := make(map[string]interface{})
	err = json.Unmarshal(decodedClaimsData, &claims)
	if err != nil {
		log.Debug("Failed to unmarshal claims data: ", err)
		return user, fmt.Errorf("failed to unmarshal claims data: %s", err.Error())
	}

	if val, ok := claims["email"]; !ok {
		log.Debug("Failed to extract email from claims.")
		return user, fmt.Errorf("unable to extract email, please check the scopes enabled for your app. It needs `email`, `name` scopes")
	} else {
		user.Email = val.(string)
	}

	if val, ok := claims["name"]; ok {
		nameData := val.(map[string]interface{})
		if nameVal, ok := nameData["firstName"]; ok {
			givenName := nameVal.(string)
			user.GivenName = &givenName
		}

		if nameVal, ok := nameData["lastName"]; ok {
			familyName := nameVal.(string)
			user.FamilyName = &familyName
		}
	}

	return user, err
}

func processTwitterUserInfo(code, verifier string) (models.User, error) {
	user := models.User{}
	oauth2Token, err := oauth.OAuthProviders.TwitterConfig.Exchange(context.TODO(), code, oauth2.SetAuthURLParam("code_verifier", verifier))
	if err != nil {
		log.Debug("Failed to exchange code for token: ", err)
		return user, fmt.Errorf("invalid twitter exchange code: %s", err.Error())
	}

	client := http.Client{}
	req, err := http.NewRequest("GET", constants.TwitterUserInfoURL, nil)
	if err != nil {
		log.Debug("Failed to create Twitter user info request: ", err)
		return user, fmt.Errorf("error creating Twitter user info request: %s", err.Error())
	}
	req.Header = http.Header{
		"Authorization": []string{fmt.Sprintf("Bearer %s", oauth2Token.AccessToken)},
	}

	response, err := client.Do(req)
	if err != nil {
		log.Debug("Failed to request Twitter user info: ", err)
		return user, err
	}

	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		log.Debug("Failed to read Twitter user info response body: ", err)
		return user, fmt.Errorf("failed to read Twitter response body: %s", err.Error())
	}

	if response.StatusCode >= 400 {
		log.Debug("Failed to request Twitter user info: ", string(body))
		return user, fmt.Errorf("failed to request Twitter user info: %s", string(body))
	}

	responseRawData := make(map[string]interface{})
	json.Unmarshal(body, &responseRawData)

	userRawData := responseRawData["data"].(map[string]interface{})

	// log.Info(userRawData)
	// Twitter API does not return E-Mail adresses by default. For that case special privileges have
	// to be granted on a per-App basis. See https://developer.twitter.com/en/docs/twitter-api/v1/accounts-and-users/manage-account-settings/api-reference/get-account-verify_credentials

	// Currently Twitter API only provides the full name of a user. To fill givenName and familyName
	// the full name will be split at the first whitespace. This approach will not be valid for all name combinations
	nameArr := strings.SplitAfterN(userRawData["name"].(string), " ", 2)

	firstName := nameArr[0]
	lastName := ""
	if len(nameArr) == 2 {
		lastName = nameArr[1]
	}
	nickname := userRawData["username"].(string)
	profilePicture := userRawData["profile_image_url"].(string)

	user = models.User{
		GivenName:  &firstName,
		FamilyName: &lastName,
		Picture:    &profilePicture,
		Nickname:   &nickname,
	}

	return user, nil
}

// process microsoft user information
func processMicrosoftUserInfo(code string) (models.User, error) {
	user := models.User{}
	ctx := context.Background()
	oauth2Token, err := oauth.OAuthProviders.MicrosoftConfig.Exchange(ctx, code)
	if err != nil {
		log.Debug("Failed to exchange code for token: ", err)
		return user, fmt.Errorf("invalid google exchange code: %s", err.Error())
	}

	verifier := oauth.OIDCProviders.MicrosoftOIDC.Verifier(&oidc.Config{ClientID: oauth.OAuthProviders.MicrosoftConfig.ClientID})

	// Extract the ID Token from OAuth2 token.
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		log.Debug("Failed to extract ID Token from OAuth2 token")
		return user, fmt.Errorf("unable to extract id_token")
	}

	// Parse and verify ID Token payload.
	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		log.Debug("Failed to verify ID Token: ", err)
		return user, fmt.Errorf("unable to verify id_token: %s", err.Error())
	}

	if err := idToken.Claims(&user); err != nil {
		log.Debug("Failed to parse ID Token claims: ", err)
		return user, fmt.Errorf("unable to extract claims")
	}

	return user, nil
}

func updateUser(ctx *gin.Context, provider string, user models.User, inputRoles []string) (models.User, error) {
	if user.RevokedTimestamp != nil {
		log.Debug("User access revoked at: ", user.RevokedTimestamp)
		// ctx.JSON(400, gin.H{"error": "user access has been revoked"})
		return user, errors.New("user access has been revoked")
	}

	// user exists in db, check if method was google
	// if not append google to existing signup method and save it
	signupMethod := user.SignupMethods
	if !strings.Contains(signupMethod, provider) {
		signupMethod = signupMethod + "," + provider
	}
	user.SignupMethods = signupMethod

	// There multiple scenarios with roles here in social login
	// 1. user has access to protected roles + roles and trying to login
	// 2. user has not signed up for one of the available role but trying to signup.
	// 		Need to modify roles in this case

	// find the unassigned roles
	existingRoles := strings.Split(user.Roles, ",")
	unasignedRoles := []string{}
	for _, ir := range inputRoles {
		if !utils.StringSliceContains(existingRoles, ir) {
			unasignedRoles = append(unasignedRoles, ir)
		}
	}

	if len(unasignedRoles) > 0 {
		// check if it contains protected unassigned role
		hasProtectedRole := false
		for _, ur := range unasignedRoles {
			protectedRolesString, err := memorystore.Provider.GetStringStoreEnvVariable(constants.EnvKeyProtectedRoles)
			protectedRoles := []string{}
			if err != nil {
				log.Debug("Failed to get protected roles: ", err)
				protectedRolesString = ""
			} else {
				protectedRoles = strings.Split(protectedRolesString, ",")
			}
			if utils.StringSliceContains(protectedRoles, ur) {
				hasProtectedRole = true
			}
		}

		if hasProtectedRole {
			log.Debug("Invalid role. User is using protected unassigned role")
			// ctx.JSON(400, gin.H{"error": "invalid role"})
			return user, errors.New("invalid role")
		} else {
			user.Roles = user.Roles + "," + strings.Join(unasignedRoles, ",")
		}
	} else {
		user.Roles = user.Roles
	}

	user, err := db.Provider.UpdateUser(ctx, user)
	if err != nil {
		log.Debug("Failed to update user: ", err)
		// ctx.JSON(500, gin.H{"error": err.Error()})
		return user, errors.New("failed to update user")
	}

	return user, nil
}

func insertUser(ctx *gin.Context, provider string, user models.User, inputRoles []string) (models.User, error) {
	isSignupDisabled, err := memorystore.Provider.GetBoolStoreEnvVariable(constants.EnvKeyDisableSignUp)
	if err != nil {
		log.Debug("Failed to get signup disabled env variable: ", err)
		// ctx.JSON(400, gin.H{"error": err.Error()})
		return user, err
	}
	if isSignupDisabled {
		log.Debug("Failed to signup as disabled")
		// ctx.JSON(400, gin.H{"error": "signup is disabled for this instance"})
		return user, errors.New("signup is disabled for this instance")
	}
	// user not registered, register user and generate session token
	user.SignupMethods = provider
	// make sure inputRoles don't include protected roles
	hasProtectedRole := false
	for _, ir := range inputRoles {
		protectedRolesString, err := memorystore.Provider.GetStringStoreEnvVariable(constants.EnvKeyProtectedRoles)
		protectedRoles := []string{}
		if err != nil {
			log.Debug("Failed to get protected roles: ", err)
			protectedRolesString = ""
		} else {
			protectedRoles = strings.Split(protectedRolesString, ",")
		}
		if utils.StringSliceContains(protectedRoles, ir) {
			hasProtectedRole = true
		}
	}

	if hasProtectedRole {
		log.Debug("Signup is not allowed with protected roles:", inputRoles)
		// ctx.JSON(400, gin.H{"error": "invalid role"})
		return user, errors.New("invalid role")
	}

	user.Roles = strings.Join(inputRoles, ",")

	if user.Email != "<nil>" && user.Email != "" {
		now := time.Now().Unix()
		user.EmailVerifiedAt = &now
	}
	user, _ = db.Provider.AddUser(ctx, user)
	return user, nil
}
