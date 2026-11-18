//go:debug tlsrsakex=1

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/kardianos/service"

	"github.com/SaaelCompany/tlswitch/internal/server"
)

func main() {
	configPath := flag.String("config", "", "путь к tlswitch.yaml")
	flag.Parse()
	path := *configPath
	if path == "" {
		path = defaultConfig()
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		abs = path
	}
	exe, _ := os.Executable()
	prg := &program{configPath: abs}
	svc, err := service.New(prg, &service.Config{
		Name:             "tlswitch",
		DisplayName:      "tlswitch",
		Description:      "Шлюз к государственным сайтам: TLS и сертификаты Минцифры на сервере",
		Arguments:        []string{"-config", abs},
		WorkingDirectory: filepath.Dir(exe),
	})
	if err != nil {
		log.Fatal(err)
	}
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "install", "uninstall", "start", "stop", "restart":
			if err := service.Control(svc, os.Args[1]); err != nil {
				log.Fatal(err)
			}
			fmt.Println(os.Args[1] + ": готово")
			return
		}
	}
	if err := svc.Run(); err != nil {
		log.Fatal(err)
	}
}

type program struct {
	configPath string
	cancel     context.CancelFunc
	done       chan struct{}
}

func (p *program) Start(service.Service) error {
	ctx, cancel := context.WithCancel(context.Background())
	p.cancel = cancel
	p.done = make(chan struct{})
	go func() {
		defer close(p.done)
		if err := run(ctx, p.configPath); err != nil {
			log.Print(err)
		}
	}()
	return nil
}

func (p *program) Stop(service.Service) error {
	if p.cancel != nil {
		p.cancel()
	}
	if p.done != nil {
		select {
		case <-p.done:
		case <-time.After(20 * time.Second):
		}
	}
	return nil
}

func run(ctx context.Context, path string) error {
	// Also stop on Ctrl+C when the process is in the foreground.
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	srv, err := server.Load(path)
	if err != nil {
		return err
	}
	log.Printf("конфигурация %s", path)
	return srv.Listen(ctx)
}

func defaultConfig() string {
	exe, err := os.Executable()
	if err == nil {
		p := filepath.Join(filepath.Dir(exe), "tlswitch.yaml")
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return "tlswitch.yaml"
}
