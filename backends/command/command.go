package command

import (
	"io"
	"net/url"
	"os"
	"os/exec"
	"syscall"
	"unsafe"

	"github.com/yudai/gotty/backends"

	"github.com/kr/pty"
)

type Options struct {
	CloseSignal int    `hcl:"close_signal" flagName:"close-signal" flagSName:"" flagDescribe:"Signal sent to the command process when gotty close it (default: SIGHUP)" default:"1"`
	TitleFormat string `hcl:"title_format" flagName:"title-format" flagSName:"" flagDescribe:"Title format of browser window" default:"GoTTY - {{ .Command }} ({{ .Hostname }})"`
}

type CommandClientContextManager struct {
	command []string
	options *Options
}

func NewCommandClientContextManager(command []string, options *Options) *CommandClientContextManager {
	return &CommandClientContextManager{command: command, options: options}
}

type CommandClientContext struct {
	cmd         *exec.Cmd
	pty         *os.File
	closeSignal int
}

func (mgr *CommandClientContextManager) New(params url.Values) (backends.ClientContext, error) {
	argv := mgr.command[1:]
	args := params["arg"]
	if len(args) != 0 {
		argv = append(argv, args...)
	}

	cmd := exec.Command(mgr.command[0], argv...)
	return &CommandClientContext{cmd: cmd, closeSignal: mgr.options.CloseSignal}, nil
}

func (context *CommandClientContext) WindowTitle() (title string, err error) {
	return context.cmd.Path, nil
}

func (context *CommandClientContext) Start() error {
	ptyIo, err := pty.Start(context.cmd)
	if err != nil {
		return err
	} else {
		context.pty = ptyIo
		return nil
	}
}

func (context *CommandClientContext) InputWriter() io.Writer {
	return context.pty
}

func (context *CommandClientContext) OutputReader() io.Reader {
	return context.pty
}

func (context *CommandClientContext) ResizeTerminal(width, height int) error {
	window := struct {
		row uint16
		col uint16
		x   uint16
		y   uint16
	}{
		uint16(height),
		uint16(width),
		0,
		0,
	}
	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		context.pty.Fd(),
		syscall.TIOCSWINSZ,
		uintptr(unsafe.Pointer(&window)),
	)
	if errno != 0 {
		return errno
	} else {
		return nil
	}
}

func (context *CommandClientContext) TearDown() error {
	context.pty.Close()
	if context.cmd != nil {
		context.cmd.Process.Signal(syscall.Signal(context.closeSignal))
		context.cmd.Wait()
	}
	return nil
}
