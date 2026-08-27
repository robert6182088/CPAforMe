package cliproxy

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/api"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
	log "github.com/sirupsen/logrus"
)

type serverListenState struct {
	host      string
	port      int
	tlsEnable bool
	tlsCert   string
	tlsKey    string
}

func normalizedServerListenState(cfg *config.Config) serverListenState {
	state := serverListenState{}
	if cfg == nil {
		return state
	}
	state.host = strings.TrimSpace(cfg.Host)
	state.port = cfg.Port
	state.tlsEnable = cfg.TLS.Enable
	state.tlsCert = strings.TrimSpace(cfg.TLS.Cert)
	state.tlsKey = strings.TrimSpace(cfg.TLS.Key)
	return state
}

func (s *Service) newAPIServer(cfg *config.Config) *api.Server {
	server := api.NewServer(cfg, s.coreManager, s.accessManager, s.configPath, s.serverOptions...)
	s.configureAPIServer(server)
	return server
}

func (s *Service) configureAPIServer(server *api.Server) {
	if s == nil || server == nil || s.wsGateway == nil {
		return
	}
	server.AttachWebsocketRoute(s.wsGateway.Path(), s.wsGateway.Handler())
	server.SetWebsocketAuthChangeHandler(func(oldEnabled, newEnabled bool) {
		if oldEnabled == newEnabled {
			return
		}
		if !oldEnabled && newEnabled {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if errStop := s.wsGateway.Stop(ctx); errStop != nil {
				log.Warnf("failed to reset websocket connections after ws-auth change %t -> %t: %v", oldEnabled, newEnabled, errStop)
				return
			}
			log.Debugf("ws-auth enabled; existing websocket sessions terminated to enforce authentication")
			return
		}
		log.Debugf("ws-auth disabled; existing websocket sessions remain connected")
	})
}

func (s *Service) startAPIServerLocked() {
	if s == nil || s.server == nil {
		return
	}
	s.serverGeneration++
	generation := s.serverGeneration
	server := s.server
	go func() {
		if errStart := server.Start(); errStart != nil {
			s.publishAPIServerError(generation, errStart)
		}
	}()
}

func (s *Service) publishAPIServerError(generation uint64, err error) {
	if s == nil || err == nil {
		return
	}
	s.serverLifecycleMu.Lock()
	current := generation == s.serverGeneration
	s.serverLifecycleMu.Unlock()
	if !current {
		log.Debugf("ignored stale API server error after restart: %v", err)
		return
	}
	if s.serverErr == nil {
		log.Errorf("API server error: %v", err)
		return
	}
	select {
	case s.serverErr <- err:
	default:
		log.Errorf("API server error while previous error is pending: %v", err)
	}
}

func (s *Service) startInitialAPIServer() {
	if s == nil {
		return
	}
	s.serverLifecycleMu.Lock()
	defer s.serverLifecycleMu.Unlock()
	s.appliedServerListenState = nil
	if s.cfg != nil {
		state := normalizedServerListenState(s.cfg)
		s.appliedServerListenState = &state
	}
	s.startAPIServerLocked()
}

func (s *Service) applyServerListenConfig(ctx context.Context, cfg *config.Config) bool {
	if s == nil || cfg == nil {
		return false
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if errContext := ctx.Err(); errContext != nil {
		return false
	}

	nextState := normalizedServerListenState(cfg)
	s.serverLifecycleMu.Lock()
	defer s.serverLifecycleMu.Unlock()
	if s.appliedServerListenState != nil && *s.appliedServerListenState == nextState {
		return true
	}
	if s.server == nil {
		s.appliedServerListenState = &nextState
		return true
	}

	if errValidate := api.ValidateTLSConfig(cfg, s.configPath); errValidate != nil {
		log.WithError(errValidate).Warn("rejected API server listener reload")
		return false
	}

	oldServer := s.server
	previousGeneration := s.serverGeneration
	s.serverGeneration++
	stopCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if errStop := oldServer.Stop(stopCtx); errStop != nil {
		s.serverGeneration = previousGeneration
		log.WithError(errStop).Error("failed to stop API server during listener reload")
		return false
	}
	if errContext := ctx.Err(); errContext != nil {
		return false
	}

	s.server = s.newAPIServer(cfg)
	s.appliedServerListenState = &nextState
	s.startAPIServerLocked()
	log.Infof("API server listener reloaded on %s", listenAddressForLog(nextState))
	return true
}

func listenAddressForLog(state serverListenState) string {
	scheme := "http"
	if state.tlsEnable {
		scheme = "https"
	}
	host := state.host
	if host == "" {
		host = "0.0.0.0"
	}
	return fmt.Sprintf("%s://%s:%d", scheme, host, state.port)
}
