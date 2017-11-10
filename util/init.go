package util

// Must is a helper that wraps a call to a function returning (string, error)
// and panics if the error is non-nil. It is intended for use in variable initializations
// such as
//	var str = util.Must(os.Executable())
func Must(dir string, err error) string {
	if err != nil {
		panic(err)
	}
	return dir
}
