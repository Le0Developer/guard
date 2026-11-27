package main

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/le0developer/guard/internal/app"
	"github.com/le0developer/guard/internal/db"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	if err := run(); err != nil {
		slog.Error("Guard stopped", "error", err)
		os.Exit(1)
	}
}
func run() error {
	c, err := app.LoadConfig()
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	pool, err := pgxpool.New(ctx, c.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()
	startup, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err = pool.Ping(startup); err != nil {
		return err
	}
	if err = db.Migrate(startup, pool); err != nil {
		return err
	}
	a, err := app.New(pool, c)
	if err != nil {
		return err
	}
	if err = a.Bootstrap(startup); err != nil {
		return err
	}
	public, err := net.Listen("tcp", c.ListenAddr)
	if err != nil {
		return err
	}
	defer public.Close()
	private, err := net.Listen("tcp", c.ForwardAuthListenAddr)
	if err != nil {
		return err
	}
	defer private.Close()
	makeServer := func(h http.Handler) *http.Server {
		return &http.Server{Handler: h, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32 << 10}
	}
	servers := []*http.Server{makeServer(a.Handler()), makeServer(a.ForwardHandler())}
	failed := make(chan error, 2)
	go func() { failed <- servers[0].Serve(public) }()
	go func() { failed <- servers[1].Serve(private) }()
	go a.Background(ctx)
	slog.Info("Guard listening", "public", public.Addr(), "forwardauth", private.Addr())
	select {
	case <-ctx.Done():
	case err = <-failed:
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
	}
	stop()
	shutdown, done := context.WithTimeout(context.Background(), 10*time.Second)
	defer done()
	for _, server := range servers {
		if e := server.Shutdown(shutdown); e != nil {
			server.Close()
			if err == nil {
				err = e
			}
		}
	}
	return err
}
