package commands

type NotificationsCmd struct{}

func (cmd *NotificationsCmd) Execute(args []string) error {
	_, err := Ctx.Notifications()
	return err
}
