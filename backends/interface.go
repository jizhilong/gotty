package backends

import (
	"io"
	"net/url"
)

type ClientContextManager interface {
	New(params url.Values) (ClientContext, error)
}

type ClientContext interface {
	WindowTitle() (string, error)
	Start() error
	InputWriter() io.Writer
	OutputReader() io.Reader
	ResizeTerminal(width, height int) error
	TearDown() error
}
