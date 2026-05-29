package testhelper

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/simulator"
	"github.com/google/go-tpm/tpm2/transport/tcp"
)

var (
	tpmSimPath = flag.String("tpm-sim-path", "", "Path to a TPM simulator binary")
)

type process struct {
	tb   testing.TB
	cmd  *exec.Cmd
	dir  string
	conn *tcp.TPM
}

func startProcess(tb testing.TB, path string) *process {
	dir, err := os.MkdirTemp("", "tpm-sim-*")
	if err != nil {
		tb.Fatalf("failed to create temp dir: %v", err)
	}

	keep := false
	defer func() {
		if !keep {
			os.RemoveAll(dir)
		}
	}()

	cmd := exec.Command(path, "--pick_ports")
	cmd.Dir = dir
	if err := cmd.Start(); err != nil {
		tb.Fatalf("failed to start simulator process: %v", err)
	}
	defer func() {
		if !keep {
			cmd.Process.Kill()
			cmd.Wait()
		}
	}()

	cmdPort, platPort, err := readPorts(dir)
	if err != nil {
		tb.Fatalf("failed to read ports: %v", err)
	}
	conn, err := tcp.Open(tcp.Config{
		CommandAddress:  fmt.Sprintf("127.0.0.1:%d", cmdPort),
		PlatformAddress: fmt.Sprintf("127.0.0.1:%d", platPort),
	})
	if err != nil {
		tb.Fatalf("failed to open TCP connection to simulator: %v", err)
	}
	defer func() {
		if !keep {
			conn.Close()
		}
	}()

	if err := conn.PowerOn(); err != nil {
		tb.Fatalf("failed to power on simulator: %v", err)
	}

	_, err = tpm2.Startup{
		StartupType: tpm2.TPMSUClear,
	}.Execute(conn)
	if err != nil {
		tb.Fatalf("failed to startup simulator: %v", err)
	}

	keep = true
	return &process{
		tb:   tb,
		cmd:  cmd,
		dir:  dir,
		conn: conn,
	}
}

func (p *process) Send(cmd []byte) ([]byte, error) {
	rsp, err := p.conn.Send(cmd)
	if err == nil {
		if hdr, err := tpm2.Unmarshal[tpm2.TPMRspHeader](rsp); err == nil {
			if hdr.ResponseCode == tpm2.TPMRCRetry {
				return p.conn.Send(cmd)
			}
		}
	}
	return rsp, err
}

// Close implements the TPMCloser interface.
func (p *process) Close() error {
	var err error
	if err = p.conn.Stop(); err != nil {
		p.tb.Errorf("failed to stop simulator: %v", err)
	}
	if err = p.conn.Close(); err != nil {
		p.tb.Errorf("failed to close simulator connection: %v", err)
	}
	if err = p.cmd.Wait(); err != nil {
		p.tb.Errorf("failed to wait for simulator process: %v", err)
	}
	if err = os.RemoveAll(p.dir); err != nil {
		p.tb.Errorf("failed to remove temp dir %q: %v", p.dir, err)
	}
	return err // Report all errors but only return the last one
}

func Open(tb testing.TB) transport.TPMCloser {
	if *tpmSimPath != "" {
		return startProcess(tb, *tpmSimPath)
	}
	tpm, err := simulator.OpenSimulator()
	if err != nil {
		tb.Fatalf("Unable to OpenSimulator: %v", err)
	}
	return tpm
}

func readPorts(dir string) (cmdPort, platPort int, err error) {
	deadline := time.Now().Add(5 * time.Second)
	for {
		if time.Now().After(deadline) {
			return 0, 0, fmt.Errorf("timed out waiting for simulator port files")
		}

		cmdPortBytes, err1 := os.ReadFile(filepath.Join(dir, "command.port"))
		platPortBytes, err2 := os.ReadFile(filepath.Join(dir, "platform.port"))
		if err1 == nil && err2 == nil {
			cmdPortStr := strings.TrimSpace(string(cmdPortBytes))
			platPortStr := strings.TrimSpace(string(platPortBytes))
			if cmdPortStr != "" && platPortStr != "" {
				cmdPort, err1 := strconv.Atoi(cmdPortStr)
				platPort, err2 := strconv.Atoi(platPortStr)
				if err1 == nil && err2 == nil {
					return cmdPort, platPort, nil
				}
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
}
