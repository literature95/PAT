// Package cli is a thin terminal adapter: it only calls app, never gateways.
package cli

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/pat-toolkit/pat/app"
)

// Dispatch sends one line to the shared core: "/" goes to command routing,
// everything else to the agent loop. Both converge on the same permission
// engine and event bus.
func Dispatch(ctx context.Context, a *app.App, line string) (string, error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return "", nil
	}
	if strings.HasPrefix(line, "/") {
		return a.Command(ctx, line)
	}
	return a.HandleMessage(ctx, line)
}

// Run is the interactive REPL.
func Run(ctx context.Context, a *app.App, in io.Reader, out io.Writer) error {
	s := a.Sessions.Current()
	if s != nil {
		fmt.Fprintf(out, "[pat] session=%s experiment=%s backend=%s provider=%s\n",
			s.ID, s.ExperimentID, a.BackendInfo, a.Provider.Name())
	}
	fmt.Fprintln(out, "输入 /help 查看命令；输入自然语言走 Agent loop；/quit 退出。")
	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 64*1024), 2*1024*1024)
	for {
		fmt.Fprint(out, "pat » ")
		if !scanner.Scan() {
			break
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if line == "/quit" || line == "exit" || line == "quit" {
			fmt.Fprintln(out, "bye")
			break
		}
		answer, err := Dispatch(ctx, a, line)
		if err != nil {
			fmt.Fprintln(out, "✗ "+err.Error())
			continue
		}
		if answer != "" {
			fmt.Fprintln(out, answer)
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	return a.Sessions.End(ctx)
}

// OneShot runs a single command (pat -c "…").
func OneShot(ctx context.Context, a *app.App, line string, out io.Writer) error {
	answer, err := Dispatch(ctx, a, line)
	if err != nil {
		return err
	}
	if answer != "" {
		fmt.Fprintln(out, answer)
	}
	return a.Sessions.End(ctx)
}

// EventPrinter shows a compact live view for -watch style demos.
func EventPrinter(ctx context.Context, a *app.App, out io.Writer) {
	ch, cancel := a.Bus.Subscribe(sessionID(a))
	defer cancel()
	for {
		select {
		case <-ctx.Done():
			return
		case e, ok := <-ch:
			if !ok {
				return
			}
			fmt.Fprintf(out, "[event] #%d %s %s %s\n", e.Seq, e.Type, e.Actor, e.RequestID)
		}
	}
}

func sessionID(a *app.App) string {
	if s := a.Sessions.Current(); s != nil {
		return s.ID
	}
	return ""
}
