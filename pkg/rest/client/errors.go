package client

type NotFoundError struct {
	msg string
}

func (err NotFoundError) Error() string {
	return err.msg
}

func NewNotFoundError(msg string) error {
	return NotFoundError{
		msg: msg,
	}
}

type AlreadyExistsError struct {
	msg string
}

func (err AlreadyExistsError) Error() string {
	return err.msg
}

func NewAlreadyExistsError(msg string) error {
	return AlreadyExistsError{
		msg: msg,
	}
}
