package commands

type CheckNotificationsCmd struct {
	Args struct {
		NotificationsIds []uint64 `positional-arg-name:"notificationsids" required:"true"`
	} `positional-args:"true"`
}

func (cmd *CheckNotificationsCmd) Execute(args []string) error {
	_, err := Ctx.CheckNotifications(cmd.Args.NotificationsIds)
	return err
}
