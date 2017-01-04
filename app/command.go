package app

import (
	"github.com/kr/pty"
	"io"
	"net/url"
	"os"
	"os/exec"
	"syscall"
	"unsafe"
)

type CommandClientContextManager struct {
	command     []string
	closeSignal int
}

type CommandClientContext struct {
	cmd         *exec.Cmd
	pty         *os.File
	closeSignal int
}

func (mgr *CommandClientContextManager) New(params url.Values) (ClientContext, error) {
	argv := mgr.command[1:]
	args := params["arg"]
	if len(args) != 0 {
		argv = append(argv, args...)
	}

	cmd := exec.Command(mgr.command[0], argv...)
	return &CommandClientContext{cmd: cmd, closeSignal: mgr.closeSignal}, nil
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
	context.cmd.Process.Signal(syscall.Signal(context.closeSignal))
	context.cmd.Wait()
	return nil
}
