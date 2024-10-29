package resolvers

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"github.com/spruceid/siwe-go"

	"github.com/authorizerdev/authorizer/server/constants"
	"github.com/authorizerdev/authorizer/server/cookie"
	"github.com/authorizerdev/authorizer/server/db"
	"github.com/authorizerdev/authorizer/server/db/models"
	"github.com/authorizerdev/authorizer/server/graph/model"
	"github.com/authorizerdev/authorizer/server/memorystore"
	"github.com/authorizerdev/authorizer/server/token"
	"github.com/authorizerdev/authorizer/server/utils"
)

// EvmWalletLoginResolver is a resolver for mobile login mutation
func EvmWalletLoginResolver(ctx context.Context, params model.EvmWalletLoginInput) (*model.AuthResponse, error) {
	var res *model.AuthResponse
	var msg *siwe.Message

	gc, err := utils.GinContextFromContext(ctx)
	if err != nil {
		log.Debug("Failed to get GinContext: ", err)
		return res, err
	}

	log := log.WithFields(log.Fields{
		"message": params.Message,
	})

	// Parsing a SIWE Message
	msg, err = siwe.ParseMessage(params.Message)
	if err != nil {
		log.Debug("Failed to parse message: ", err)
		return res, fmt.Errorf(`bad user credentials`)
	}

	// Verifying a SIWE Message
	// TODO: Verifying timestamp and nonce
	var publicKey *ecdsa.PublicKey
	publicKey, err = msg.VerifyEIP191(params.Signature)
	if err != nil {
		log.Debug("Failed to verify EIP191 message: ", err)
		return res, fmt.Errorf(`bad user credentials`)
	}

	address := crypto.PubkeyToAddress(*publicKey)
	isSignUp := false
	provider := constants.AuthSIWEAuth

	defaultRolesString, err := memorystore.Provider.GetStringStoreEnvVariable(constants.EnvKeyDefaultRoles)
	if err != nil {
		log.Debug("Error getting default roles: ", err)
		defaultRolesString = ""
	}
	roles := strings.Split(defaultRolesString, ",")

	existingUser, err := db.Provider.GetUserByWalletAddress(ctx, address.String())
	user := models.User{}

	if err != nil {
		log.Debug("Failed to get existing user: ", err)

		isSignupDisabled, err := memorystore.Provider.GetBoolStoreEnvVariable(constants.EnvKeyDisableSignUp)
		if err != nil {
			log.Debug("Failed to get signup disabled env variable: ", err)
			return res, fmt.Errorf(`bad user credentials`)
		}
		if isSignupDisabled {
			log.Debug("Failed to signup as disabled")
			return res, fmt.Errorf(`bad user credentials`)
		}
		addressStr := address.String()

		user.WalletAddress = &addressStr

		// user not registered, register user and generate session token
		user.SignupMethods = provider
		user.Roles = defaultRolesString

		isEmailVerificationDisabled, err := memorystore.Provider.GetBoolStoreEnvVariable(constants.EnvKeyDisableEmailVerification)
		if err != nil {
			log.Debug("Error getting email verification disabled: ", err)
			isEmailVerificationDisabled = true
		}
		if isEmailVerificationDisabled {
			log.Debug("Email verification disabled")
			now := time.Now().Unix()
			user.EmailVerifiedAt = &now
		}

		if user.Email != "<nil>" && user.Email != "" {
			now := time.Now().Unix()
			user.EmailVerifiedAt = &now
		}
		user, _ = db.Provider.AddUser(ctx, user)
		// For unknown resion, this user id is difference with user id in db. Hotfix: query from db after insert
		existingUser, _ := db.Provider.GetUserByWalletAddress(ctx, address.String())
		user = existingUser
		isSignUp = true
	} else {
		user = existingUser

		isEmailVerificationDisabled, err := memorystore.Provider.GetBoolStoreEnvVariable(constants.EnvKeyDisableEmailVerification)
		if err != nil {
			log.Debug("Error getting email verification disabled: ", err)
			isEmailVerificationDisabled = true
		}
		if isEmailVerificationDisabled {
			log.Debug("Email verification disabled")
			now := time.Now().Unix()
			user.EmailVerifiedAt = &now
		}

		log.Debug("Get existing user OK: ", user.ID)
		// if user.Email != "<nil>" && user.EmailVerifiedAt == nil {
		// 	log.Debug("User email is not verified")
		// 	return res, fmt.Errorf(`email not verified`)
		// }

		if user.RevokedTimestamp != nil {
			log.Debug("User access revoked at: ", user.RevokedTimestamp)
			return res, fmt.Errorf(`user access has been revoked`)
		}

		signupMethod := existingUser.SignupMethods
		if !strings.Contains(signupMethod, provider) {
			signupMethod = signupMethod + "," + provider
		}
		user.SignupMethods = signupMethod

		user, err = db.Provider.UpdateUser(ctx, user)
		if err != nil {
			log.Debug("Failed to update user: ", err)
			return res, fmt.Errorf(err.Error())
		}
	}

	creator, err := db.Provider.GetCreatorByEmail(ctx, user.Email)
	fmt.Println(creator)
	if err == nil {
		roles = append(roles, "creator")
		user.Roles = strings.Join(roles, ",")
	}
	scope := []string{"openid", "email", "profile"}

	code := ""
	nonce := ""

	if nonce == "" {
		nonce = uuid.New().String()
	}

	authToken, err := token.CreateAuthToken(gc, user, roles, scope, constants.AuthSIWEAuth, nonce, code)
	if err != nil {
		log.Debug("Failed to create auth token", err)
		return res, err
	}

	expiresIn := authToken.AccessToken.ExpiresAt - time.Now().Unix()
	if expiresIn <= 0 {
		expiresIn = 1
	}

	res = &model.AuthResponse{
		Message:     `Logged in successfully`,
		AccessToken: &authToken.AccessToken.Token,
		IDToken:     &authToken.IDToken.Token,
		ExpiresIn:   &expiresIn,
		User:        user.AsAPIUser(),
	}

	cookie.SetSession(gc, authToken.FingerPrintHash)
	sessionStoreKey := provider + ":" + user.ID
	memorystore.Provider.SetUserSession(sessionStoreKey, constants.TokenTypeSessionToken+"_"+authToken.FingerPrint, authToken.FingerPrintHash, authToken.SessionTokenExpiresAt)
	memorystore.Provider.SetUserSession(sessionStoreKey, constants.TokenTypeAccessToken+"_"+authToken.FingerPrint, authToken.AccessToken.Token, authToken.AccessToken.ExpiresAt)

	if authToken.RefreshToken != nil {
		res.RefreshToken = &authToken.RefreshToken.Token
		memorystore.Provider.SetUserSession(sessionStoreKey, constants.TokenTypeRefreshToken+"_"+authToken.FingerPrint, authToken.RefreshToken.Token, authToken.RefreshToken.ExpiresAt)
	}

	go func() {
		if isSignUp {
			utils.RegisterEvent(ctx, constants.UserSignUpWebhookEvent, provider, user)
		} else {
			utils.RegisterEvent(ctx, constants.UserLoginWebhookEvent, provider, user)
		}
		db.Provider.AddSession(ctx, models.Session{
			UserID:    user.ID,
			UserAgent: utils.GetUserAgent(gc.Request),
			IP:        utils.GetIP(gc.Request),
		})
	}()

	return res, nil
}
