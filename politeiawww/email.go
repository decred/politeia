package main

import (
	"bytes"
	"fmt"
	"net/url"
	"text/template"

	"github.com/dajohi/goemail"

	"github.com/decred/politeia/politeiawww/api/v1"
	"github.com/decred/politeia/politeiawww/database"
)

const (
	fromAddress      = "noreply@decred.org"
	politeiaMailName = "Politeia"
)

func createBody(tpl *template.Template, tplData interface{}) (string, error) {
	var buf bytes.Buffer
	err := tpl.Execute(&buf, tplData)
	if err != nil {
		return "", err
	}

	return buf.String(), nil
}

func (b *backend) createEmailLink(path, email, token string) (string, error) {
	l, err := url.Parse(b.cfg.WebServerAddress + path)
	if err != nil {
		return "", err
	}

	q := l.Query()
	if email != "" {
		q.Set("email", email)
	}
	if token != "" {
		q.Set("verificationtoken", token)
	}
	l.RawQuery = q.Encode()

	return l.String(), nil
}

// sendEmail sends an email with the given subject and body, and the caller
// must supply a function which is used to add email addresses to send the
// email to.
func (b *backend) sendEmail(
	subject, body string,
	addToAddressesFn func(*goemail.Message) error,
) error {
	msg := goemail.NewMessage(fromAddress, subject, body)
	err := addToAddressesFn(msg)
	if err != nil {
		return err
	}

	msg.SetName(politeiaMailName)
	return b.cfg.SMTP.Send(msg)
}

// sendEmailTo sends an email with the given subject and body to a
// single address.
func (b *backend) sendEmailTo(subject, body, toAddress string) error {
	return b.sendEmail(subject, body, func(msg *goemail.Message) error {
		msg.AddTo(toAddress)
		return nil
	})
}

// emailNewUserVerificationLink emails the link with the new user verification token
// if the email server is set up.
func (b *backend) emailNewUserVerificationLink(email, token, username string) error {
	if b.cfg.SMTP == nil {
		return nil
	}

	link, err := b.createEmailLink(v1.RouteVerifyNewUser, email,
		token)
	if err != nil {
		return err
	}

	tplData := newUserEmailTemplateData{
		Username: username,
		Email:    email,
		Link:     link,
	}

	subject := "Verify Your Email"
	body, err := createBody(templateNewUserEmail, &tplData)
	if err != nil {
		return err
	}

	return b.sendEmailTo(subject, body, email)
}

// emailResetPasswordVerificationLink emails the link with the reset password
// verification token if the email server is set up.
func (b *backend) emailResetPasswordVerificationLink(email, token string) error {
	if b.cfg.SMTP == nil {
		return nil
	}

	link, err := b.createEmailLink(v1.RouteResetPassword, email,
		token)
	if err != nil {
		return err
	}

	tplData := resetPasswordEmailTemplateData{
		Email: email,
		Link:  link,
	}

	subject := "Reset Your Password"
	body, err := createBody(templateResetPasswordEmail, &tplData)
	if err != nil {
		return err
	}

	return b.sendEmailTo(subject, body, email)
}

// emailAuthorForVettedProposal sends an email notification for a new
// proposal becoming vetted to the proposal's author.
func (b *backend) emailAuthorForVettedProposal(
	proposal *v1.ProposalRecord,
	authorUser *database.User,
	adminUser *database.User,
) error {
	if b.cfg.SMTP == nil {
		return nil
	}

	l, err := url.Parse(b.cfg.WebServerAddress + "/proposals/" +
		proposal.CensorshipRecord.Token)
	if err != nil {
		return err
	}

	if authorUser.EmailNotifications&
		uint64(v1.NotificationEmailMyProposalStatusChange) == 0 {
		return nil
	}

	tplData := proposalStatusChangeTemplateData{
		Link:               l.String(),
		Name:               proposal.Name,
		StatusChangeReason: proposal.StatusChangeMessage,
	}

	subject := "Your Proposal Has Been Published"
	body, err := createBody(templateProposalVettedForAuthor, &tplData)
	if err != nil {
		return err
	}

	return b.sendEmailTo(subject, body, authorUser.Email)
}

// emailAuthorForCensoredProposal sends an email notification for a new
// proposal becoming censored to the proposal's author.
func (b *backend) emailAuthorForCensoredProposal(
	proposal *v1.ProposalRecord,
	authorUser *database.User,
	adminUser *database.User,
) error {
	if b.cfg.SMTP == nil {
		return nil
	}

	l, err := url.Parse(b.cfg.WebServerAddress + "/proposals/" +
		proposal.CensorshipRecord.Token)
	if err != nil {
		return err
	}

	if authorUser.EmailNotifications&
		uint64(v1.NotificationEmailMyProposalStatusChange) == 0 {
		return nil
	}

	tplData := proposalStatusChangeTemplateData{
		Link:               l.String(),
		Name:               proposal.Name,
		StatusChangeReason: proposal.StatusChangeMessage,
	}

	subject := "Your Proposal Has Been Censored"
	body, err := createBody(templateProposalCensoredForAuthor, &tplData)
	if err != nil {
		return err
	}

	return b.sendEmailTo(subject, body, authorUser.Email)
}

// emailUsersForVettedProposal sends an email notification for a new
// proposal becoming vetted.
func (b *backend) emailUsersForVettedProposal(
	proposal *v1.ProposalRecord,
	authorUser *database.User,
	adminUser *database.User,
) error {
	if b.cfg.SMTP == nil {
		return nil
	}

	// Create the template data.
	l, err := url.Parse(b.cfg.WebServerAddress + "/proposals/" +
		proposal.CensorshipRecord.Token)
	if err != nil {
		return err
	}

	tplData := proposalStatusChangeTemplateData{
		Link:     l.String(),
		Name:     proposal.Name,
		Username: authorUser.Username,
	}

	// Send email to users.
	subject := "New Proposal Published"
	body, err := createBody(templateProposalVetted, &tplData)
	if err != nil {
		return err
	}

	return b.sendEmail(subject, body, func(msg *goemail.Message) error {
		// Add user emails to the goemail.Message
		return b.db.AllUsers(func(user *database.User) {
			// Don't notify the user under certain conditions.
			if user.NewUserPaywallTx == "" || user.Deactivated ||
				user.ID == adminUser.ID || user.ID == authorUser.ID ||
				(user.EmailNotifications&
					uint64(v1.NotificationEmailRegularProposalVetted)) == 0 {
				return
			}

			msg.AddBCC(user.Email)
		})
	})
}

// emailUsersForEditedProposal sends an email notification for a proposal
// being edited.
func (b *backend) emailUsersForEditedProposal(
	proposal *v1.ProposalRecord,
	authorUser *database.User,
) error {
	if b.cfg.SMTP == nil {
		return nil
	}

	// Create the template data.
	l, err := url.Parse(b.cfg.WebServerAddress + "/proposals/" +
		proposal.CensorshipRecord.Token)
	if err != nil {
		return err
	}

	tplData := proposalEditedTemplateData{
		Link:     l.String(),
		Name:     proposal.Name,
		Version:  proposal.Version,
		Username: authorUser.Username,
	}

	// Send email to users.
	subject := "Proposal Edited"
	body, err := createBody(templateProposalEdited, &tplData)
	if err != nil {
		return err
	}

	return b.sendEmail(subject, body, func(msg *goemail.Message) error {
		// Add user emails to the goemail.Message
		return b.db.AllUsers(func(user *database.User) {
			// Don't notify the user under certain conditions.
			if user.NewUserPaywallTx == "" || user.Deactivated ||
				user.ID == authorUser.ID ||
				(user.EmailNotifications&
					uint64(v1.NotificationEmailRegularProposalEdited)) == 0 {
				return
			}

			msg.AddBCC(user.Email)
		})
	})
}

// emailUsersForProposalVoteStarted sends an email notification for a proposal
// entering the voting state.
func (b *backend) emailUsersForProposalVoteStarted(
	proposal *v1.ProposalRecord,
	authorUser *database.User,
	adminUser *database.User,
) error {
	if b.cfg.SMTP == nil {
		return nil
	}

	// Create the template data.
	l, err := url.Parse(b.cfg.WebServerAddress + "/proposals/" +
		proposal.CensorshipRecord.Token)
	if err != nil {
		return err
	}

	tplData := proposalVoteStartedTemplateData{
		Link:     l.String(),
		Name:     proposal.Name,
		Username: authorUser.Username,
	}

	// Send email to author.
	if authorUser.EmailNotifications&
		uint64(v1.NotificationEmailMyProposalVoteStarted) != 0 {

		subject := "Your Proposal Has Started Voting"
		body, err := createBody(templateProposalVoteStartedForAuthor, &tplData)
		if err != nil {
			return err
		}

		err = b.sendEmailTo(subject, body, authorUser.Email)
		if err != nil {
			return err
		}
	}

	subject := "Voting Started for Proposal"
	body, err := createBody(templateProposalVoteStarted, &tplData)
	if err != nil {
		return err
	}

	return b.sendEmail(subject, body, func(msg *goemail.Message) error {
		// Add user emails to the goemail.Message
		return b.db.AllUsers(func(user *database.User) {
			// Don't notify the user under certain conditions.
			if user.NewUserPaywallTx == "" || user.Deactivated ||
				user.ID == adminUser.ID ||
				user.ID == authorUser.ID ||
				(user.EmailNotifications&
					uint64(v1.NotificationEmailRegularProposalVoteStarted)) == 0 {
				return
			}

			msg.AddBCC(user.Email)
		})
	})
}

func (b *backend) emailAdminsForNewSubmittedProposal(token string, propName string, username string, userEmail string) error {
	if b.cfg.SMTP == nil {
		return nil
	}

	l, err := url.Parse(b.cfg.WebServerAddress + "/proposals/" + token)
	if err != nil {
		return err
	}

	tplData := newProposalSubmittedTemplateData{
		Link:     l.String(),
		Name:     propName,
		Username: username,
		Email:    userEmail,
	}

	subject := "New Proposal Submitted"
	body, err := createBody(templateNewProposalSubmitted, &tplData)
	if err != nil {
		return err
	}

	return b.sendEmail(subject, body, func(msg *goemail.Message) error {
		// Add admin emails to the goemail.Message
		return b.db.AllUsers(func(user *database.User) {
			if !user.Admin || user.Deactivated ||
				(user.EmailNotifications&
					uint64(v1.NotificationEmailAdminProposalNew) == 0) {
				return
			}
			msg.AddBCC(user.Email)
		})
	})
}

func (b *backend) emailAdminsForProposalVoteAuthorized(
	proposal *v1.ProposalRecord,
	authorUser *database.User,
) error {
	if b.cfg.SMTP == nil {
		return nil
	}

	l, err := url.Parse(b.cfg.WebServerAddress + "/proposals/" + proposal.CensorshipRecord.Token)
	if err != nil {
		return err
	}

	tplData := proposalVoteAuthorizedTemplateData{
		Link:     l.String(),
		Name:     proposal.Name,
		Username: authorUser.Username,
		Email:    authorUser.Email,
	}

	subject := "Proposal Authorized To Start Voting"
	body, err := createBody(templateProposalVoteAuthorized, &tplData)
	if err != nil {
		return err
	}

	return b.sendEmail(subject, body, func(msg *goemail.Message) error {
		// Add admin emails to the goemail.Message
		return b.db.AllUsers(func(user *database.User) {
			if !user.Admin || user.Deactivated ||
				(user.EmailNotifications&
					uint64(v1.NotificationEmailAdminProposalVoteAuthorized) == 0) {
				return
			}
			msg.AddBCC(user.Email)
		})
	})
}

// emailAuthorForCommentOnProposal sends an email notification to a proposal
// author for a new comment.
func (b *backend) emailAuthorForCommentOnProposal(
	proposal *v1.ProposalRecord,
	authorUser *database.User,
	username string,
) error {
	if b.cfg.SMTP == nil {
		return nil
	}

	l, err := url.Parse(fmt.Sprintf("%v/proposals/%v", b.cfg.WebServerAddress,
		proposal.CensorshipRecord.Token))
	if err != nil {
		return err
	}

	if authorUser.EmailNotifications&
		uint64(v1.NotificationEmailCommentOnMyProposal) == 0 {
		return nil
	}

	tplData := commentReplyOnProposalTemplateData{
		Commenter:    username,
		ProposalName: proposal.Name,
		CommentLink:  l.String(),
	}

	subject := "New Comment On Your Proposal"
	body, err := createBody(templateCommentReplyOnProposal, &tplData)
	if err != nil {
		return err
	}

	return b.sendEmailTo(subject, body, authorUser.Email)
}

// emailAuthorForCommentOnComment sends an email notification to a comment
// author for a new comment reply.
func (b *backend) emailAuthorForCommentOnComment(
	proposal *v1.ProposalRecord,
	authorUser *database.User,
	commentID, username string,
) error {
	if b.cfg.SMTP == nil {
		return nil
	}

	l, err := url.Parse(fmt.Sprintf("%v/proposals/%v/comments/%v",
		b.cfg.WebServerAddress, proposal.CensorshipRecord.Token, commentID))
	if err != nil {
		return err
	}

	if authorUser.EmailNotifications&
		uint64(v1.NotificationEmailCommentOnMyComment) == 0 {
		return nil
	}

	tplData := commentReplyOnCommentTemplateData{
		Commenter:    username,
		ProposalName: proposal.Name,
		CommentLink:  l.String(),
	}

	subject := "New Comment On Your Comment"
	body, err := createBody(templateCommentReplyOnComment, &tplData)
	if err != nil {
		return err
	}

	return b.sendEmailTo(subject, body, authorUser.Email)
}

// emailUpdateUserKeyVerificationLink emails the link with the verification
// token used for setting a new key pair if the email server is set up.
func (b *backend) emailUpdateUserKeyVerificationLink(email, publicKey, token string) error {
	if b.cfg.SMTP == nil {
		return nil
	}

	link, err := b.createEmailLink(v1.RouteVerifyUpdateUserKey,
		"", token)
	if err != nil {
		return err
	}

	tplData := updateUserKeyEmailTemplateData{
		Email:     email,
		PublicKey: publicKey,
		Link:      link,
	}

	subject := "Verify Your New Identity"
	body, err := createBody(templateUpdateUserKeyEmail, &tplData)
	if err != nil {
		return err
	}

	return b.sendEmailTo(subject, body, email)
}

// emailUserLocked notifies the user its account has been locked and emails the
// link with the reset password verification token if the email server is set
// up.
func (b *backend) emailUserLocked(email string) error {
	if b.cfg.SMTP == nil {
		return nil
	}

	link, err := b.createEmailLink(ResetPasswordGuiRoute,
		email, "")
	if err != nil {
		return err
	}

	tplData := userLockedResetPasswordEmailTemplateData{
		Email: email,
		Link:  link,
	}

	subject := "Locked Account - Reset Your Password"
	body, err := createBody(templateUserLockedResetPassword, &tplData)
	if err != nil {
		return err
	}

	return b.sendEmailTo(subject, body, email)
}
