package app

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/fatih/structs"
	"github.com/fsouza/go-dockerclient"
	"github.com/gorilla/websocket"
)

type clientContext struct {
	app           *App
	request       *http.Request
	containerId   string
	exec          *docker.Exec
	stdinReader   io.ReadCloser  // read by docker client
	stdinWriter   io.WriteCloser // write by our code when proxying inputs from ws
	stdoutReader  io.ReadCloser  // read by our code, will be proxied to ws
	stdoutWriter  io.WriteCloser // write by docker client
	connection    *websocket.Conn
	stoppedSignal chan bool
	writeMutex    *sync.Mutex
}

const (
	Input          = '0'
	Ping           = '1'
	ResizeTerminal = '2'
)

const (
	Output         = '0'
	Pong           = '1'
	SetWindowTitle = '2'
	SetPreferences = '3'
	SetReconnect   = '4'
)

var Command []string = []string{"env", "TERM=xterm-256color", "sh", "-c", "if command -v bash > /dev/null;then exec bash;else exec sh;fi"}

type argResizeTerminal struct {
	Columns float64
	Rows    float64
}

type ContextVars struct {
	Container  string
	Pid        int
	Hostname   string
	RemoteAddr string
}

func NewClientContext(app *App, request *http.Request, containerId string, connection *websocket.Conn) (context *clientContext, err error) {
	var exec *docker.Exec
	opts := docker.CreateExecOptions{
		Container:    containerId,
		AttachStdin:  true,
		AttachStdout: true,
		AttachStderr: true,
		Tty:          true,
		Cmd:          Command,
	}

	if exec, err = app.dockerClient.CreateExec(opts); err != nil {
		return
	}
	stdinPipeReader, stdinPipeWriter := io.Pipe()
	stdoutPipeReader, stdoutPipeWriter := io.Pipe()

	context = &clientContext{
		app:           app,
		request:       request,
		containerId:   containerId,
		exec:          exec,
		stdinReader:   stdinPipeReader,
		stdinWriter:   stdinPipeWriter,
		stdoutReader:  stdoutPipeReader,
		stdoutWriter:  stdoutPipeWriter,
		connection:    connection,
		writeMutex:    &sync.Mutex{},
		stoppedSignal: make(chan bool),
	}
	return
}

func (context *clientContext) goHandleClient() {
	defer context.stop()
	go context.processSend()
	go context.processReceive()
	go context.waitForStop()

	if err := context.app.dockerClient.StartExec(context.exec.ID, docker.StartExecOptions{
		Detach:       false,
		OutputStream: context.stdoutWriter,
		ErrorStream:  context.stdoutWriter,
		InputStream:  context.stdinReader,
		RawTerminal:  false,
	}); err != nil {
		log.Printf("failed to start exec %v\n", err)
	} else {
		log.Printf("session closed!")
	}

	log.Printf("exec in %s stopped", context.containerId)
}

func (context *clientContext) processSend() {
	defer context.stop()
	buf := make([]byte, 1024)

	if err := context.sendInitialize(); err != nil {
		log.Printf(err.Error())
		context.stop()
		return
	}

	for {
		size, err := context.stdoutReader.Read(buf)
		if err != nil {
			log.Printf("exec exited for: %s", context.request.RemoteAddr)
			return
		}
		safeMessage := base64.StdEncoding.EncodeToString([]byte(buf[:size]))
		if err = context.write(append([]byte{Output}, []byte(safeMessage)...)); err != nil {
			log.Printf(err.Error())
			return
		}
	}
}

func (context *clientContext) write(data []byte) error {
	context.writeMutex.Lock()
	defer context.writeMutex.Unlock()
	return context.connection.WriteMessage(websocket.TextMessage, data)
}

func (context *clientContext) sendInitialize() error {
	var truncatedCid string
	hostname, _ := os.Hostname()
	if len(context.containerId) < 32 {
		truncatedCid = context.containerId
	} else {
		truncatedCid = context.containerId[:32]
	}
	titleVars := ContextVars{
		Container:  truncatedCid,
		Pid:        0,
		Hostname:   hostname,
		RemoteAddr: context.request.RemoteAddr,
	}

	titleBuffer := new(bytes.Buffer)
	if err := context.app.titleTemplate.Execute(titleBuffer, titleVars); err != nil {
		return err
	}
	if err := context.write(append([]byte{SetWindowTitle}, titleBuffer.Bytes()...)); err != nil {
		return err
	}

	prefStruct := structs.New(context.app.options.Preferences)
	prefMap := prefStruct.Map()
	htermPrefs := make(map[string]interface{})
	for key, value := range prefMap {
		rawKey := prefStruct.Field(key).Tag("hcl")
		if _, ok := context.app.options.RawPreferences[rawKey]; ok {
			htermPrefs[strings.Replace(rawKey, "_", "-", -1)] = value
		}
	}
	prefs, err := json.Marshal(htermPrefs)
	if err != nil {
		return err
	}

	if err := context.write(append([]byte{SetPreferences}, prefs...)); err != nil {
		return err
	}
	if context.app.options.EnableReconnect {
		reconnect, _ := json.Marshal(context.app.options.ReconnectTime)
		if err := context.write(append([]byte{SetReconnect}, reconnect...)); err != nil {
			return err
		}
	}
	return nil
}

func (context *clientContext) processReceive() {
	defer context.stop()

	for {
		_, data, err := context.connection.ReadMessage()
		if err != nil {
			log.Print("error happend when reading from ws ", err)
			return
		}
		if len(data) == 0 {
			log.Print("An error has occured")
			return
		}

		switch data[0] {
		case Input:
			if !context.app.options.PermitWrite {
				break
			}

			_, err := context.stdinWriter.Write(data[1:])
			if err != nil {
				log.Print("failed to write to exec's stdin ", err)
				return
			}

		case Ping:
			if err := context.write([]byte{Pong}); err != nil {
				log.Print("failed to send back pong ", err)
				return
			}
		case ResizeTerminal:
			var args argResizeTerminal
			err = json.Unmarshal(data[1:], &args)
			if err != nil {
				log.Print("Malformed remote command")
				return
			}

			width, height := int(args.Columns), int(args.Rows)
			if width >= 0 && height >= 0 {
				err = context.app.dockerClient.ResizeExecTTY(context.exec.ID, height, width)
				if err != nil {
					log.Printf("failed to resize exec %v to %vx%v\n", context.exec.ID, width, height)
					return
				}
			} else {
				log.Printf("invalid new tty size %vx%v\n", width, height)
				return
			}

		default:
			log.Print("Unknown message type")
			return
		}
	}
}

func (context *clientContext) stop() {
	select {
	case context.stoppedSignal <- true:
		log.Printf("stopping context")
	default:
		log.Printf("this context has already stopped")
	}
}

func (context *clientContext) cleanUp() {
	exitKeySeq := []byte{4, 4}
	context.stdinWriter.Write(exitKeySeq)
	context.connection.Close()
	context.stdinReader.Close()
	context.stdoutWriter.Close()
	context.app.connections--
	if context.app.options.MaxConnection != 0 {
		log.Printf("Connection closed: %s, connections: %d/%d",
			context.request.RemoteAddr, context.app.connections, context.app.options.MaxConnection)
	} else {
		log.Printf("Connection closed: %s, connections: %d",
			context.request.RemoteAddr, context.app.connections)
	}
}

func (context *clientContext) waitForStop() {
	defer context.app.server.FinishRoutine()

	<-context.stoppedSignal
	context.cleanUp()
}
