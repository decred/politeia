package main

import (
	"net/http"
	"text/template"

	v1 "github.com/decred/politeia/politeiawww/api/v1"
)

var (
	templateNewUserEmail = template.Must(
		template.New("new_user_email_template").Parse(templateNewUserEmailRaw))
	templateResetPasswordEmail = template.Must(
		template.New("reset_password_email_template").Parse(templateResetPasswordEmailRaw))
	templateUpdateUserKeyEmail = template.Must(
		template.New("update_user_key_email_template").Parse(templateUpdateUserKeyEmailRaw))
	templateUserLockedResetPassword = template.Must(
		template.New("user_locked_reset_password").Parse(templateUserLockedResetPasswordRaw))
	templateUserPasswordChanged = template.Must(
		template.New("user_changed_password").Parse(templateUserPasswordChangedRaw))
)

func (p *politeiawww) setUserWWWRoutes() {
	// Public routes
	p.addRoute(http.MethodPost, v1.RouteNewUser, p.handleNewUser,
		permissionPublic)
	p.addRoute(http.MethodGet, v1.RouteVerifyNewUser,
		p.handleVerifyNewUser, permissionPublic)
	p.addRoute(http.MethodPost, v1.RouteResendVerification,
		p.handleResendVerification, permissionPublic)
	p.addRoute(http.MethodPost, v1.RouteLogin, p.handleLogin,
		permissionPublic)
	p.addRoute(http.MethodPost, v1.RouteLogout, p.handleLogout,
		permissionPublic)
	p.addRoute(http.MethodPost, v1.RouteResetPassword,
		p.handleResetPassword, permissionPublic)
	p.addRoute(http.MethodGet, v1.RouteUserDetails,
		p.handleUserDetails, permissionPublic)

	// Routes that require being logged in.
	p.addRoute(http.MethodPost, v1.RouteSecret, p.handleSecret,
		permissionLogin)
	p.addRoute(http.MethodGet, v1.RouteUserMe, p.handleMe, permissionLogin)
	p.addRoute(http.MethodPost, v1.RouteUpdateUserKey,
		p.handleUpdateUserKey, permissionLogin)
	p.addRoute(http.MethodPost, v1.RouteVerifyUpdateUserKey,
		p.handleVerifyUpdateUserKey, permissionLogin)
	p.addRoute(http.MethodPost, v1.RouteChangeUsername,
		p.handleChangeUsername, permissionLogin)
	p.addRoute(http.MethodPost, v1.RouteChangePassword,
		p.handleChangePassword, permissionLogin)
	p.addRoute(http.MethodGet, v1.RouteVerifyUserPayment,
		p.handleVerifyUserPayment, permissionLogin)
	p.addRoute(http.MethodPost, v1.RouteEditUser,
		p.handleEditUser, permissionLogin)

	// Routes that require being logged in as an admin user.
	p.addRoute(http.MethodGet, v1.RouteUsers,
		p.handleUsers, permissionAdmin)
	p.addRoute(http.MethodPut, v1.RouteUserPaymentsRescan,
		p.handleUserPaymentsRescan, permissionAdmin)
	p.addRoute(http.MethodPost, v1.RouteManageUser,
		p.handleManageUser, permissionAdmin)
}
