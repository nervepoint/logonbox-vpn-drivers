package com.logonbox.vpn.drivers.lib;

import java.io.Closeable;
import java.io.IOException;
import java.io.Reader;
import java.nio.file.Path;
import java.text.MessageFormat;
import java.text.ParseException;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.function.BiConsumer;

public final class Vpn implements Closeable {

    public final static class Builder {

        private Optional<PlatformService<?>> platformService = Optional.empty();
        private Optional<VpnConfiguration> vpnConfiguration = Optional.empty();
        private Optional<VpnPeer> vpnPeer = Optional.empty();
        private Optional<SystemConfiguration> systemConfiguration = Optional.empty();
        private Optional<BiConsumer<ActiveSession<?>, Map<String, String>>> onAddScriptEnvironment = Optional.empty();
        
        public Builder withPlatformService(PlatformService<?> platformService) {
            this.platformService = Optional.of(platformService);
            return this;
        }
        
        public Builder withVpnConfiguration(VpnConfiguration vpnConfiguration) {
            this.vpnConfiguration = Optional.of(vpnConfiguration);
            return this;
        }
        
        public Builder withVpnPeer(VpnPeer vpnPeer) {
            this.vpnPeer = Optional.of(vpnPeer);
            return this;
        }
        
        public Builder withVpnConfiguration(Path vpnConfiguration) throws IOException, ParseException {
            return withVpnConfiguration(new VpnConfiguration.Builder().fromFile(vpnConfiguration).build());
        }
        
        public Builder withVpnConfiguration(Reader vpnConfiguration) throws IOException, ParseException {
            return withVpnConfiguration(new VpnConfiguration.Builder().fromFileContent(vpnConfiguration).build());
        }
        
        public Builder withSystemConfiguration(SystemConfiguration systemConfiguration) {
            this.systemConfiguration = Optional.of(systemConfiguration);
            return this;
        }
        
        public Builder onAddScriptEnvironment(BiConsumer<ActiveSession<?>, Map<String, String>> onAddScriptEnvironment) {
            this.onAddScriptEnvironment = Optional.of(onAddScriptEnvironment);
            return this;
        }
        
        public Vpn build() throws IOException {
            return new Vpn(this);
        }
    }

    public static final Integer DEFAULT_PORT = 51820;
    
    private final PlatformService<?> platformService;
    private final Optional<BiConsumer<ActiveSession<?>, Map<String, String>>> onAddScriptEnvironment;
    private final ActiveSession<?> session;
    
    private Vpn(Builder builder) throws IOException {
        onAddScriptEnvironment = builder.onAddScriptEnvironment;
        
        var cfg = builder.vpnConfiguration.orElseThrow(() -> new IllegalStateException("No VPN configuration supplied."));
        
        /* If no specific peer, then try to find the first with an endpoint address and
         * assume that's the one to use.
         */
        var peer = builder.vpnPeer.or(() -> {
            for(var p : cfg.peers()) {
                if(p.endpointAddress().isPresent())
                    return Optional.of(p);
            }
            return Optional.empty();
        });

        /* Either start a new session, or find an existing one */
        if (builder.platformService.isPresent()) {
            platformService = builder.platformService.get();
            session = platformService.start(cfg, peer);
        } else {
            platformService = PlatformService.create();
            var active = platformService.init(new VpnSystemContext(builder.systemConfiguration, cfg));
            ActiveSession<?> found = null;
            for (var s : active) {
                if (s.configuration().publicKey().equals(cfg.publicKey())) {
                    found = s;
                    break;
                }
            }
            if (found == null) {
                session = platformService.start(cfg, peer);
            } else {
                session = found;
            }
        }
    }
    
    public PlatformService<?> platformService() {
        return platformService;
    }
    
    public VpnConfiguration configuration() {
        return session.configuration();
    }
    
    public VpnInterface<?> ip() {
        return session.ip().orElseThrow(() -> new IllegalStateException("Not active"));
    }
    
    public VpnInterfaceInformation information() throws IOException {
        return ip().information();
    }

    @Override
    public void close() throws IOException {
        session.close();
        if(platformService.context() instanceof VpnSystemContext)
            ((VpnSystemContext)platformService.context()).close();
    }
    
    class VpnSystemContext implements SystemContext, Closeable {
        private final ScheduledExecutorService queue = Executors.newSingleThreadScheduledExecutor();
        private final SystemConfiguration configuration;
        private final VpnConfiguration vpnConfiguration;
        
        VpnSystemContext(Optional<SystemConfiguration> configuration, VpnConfiguration vpnConfiguration) {
            this.configuration = configuration.orElseGet(() -> SystemConfiguration.defaultConfiguration());
            this.vpnConfiguration = vpnConfiguration;
        }

        @Override
        public ScheduledExecutorService queue() {
            return queue;
        }

        @Override
        public SystemConfiguration configuration() {
            return configuration;
        }

        @Override
        public VpnConfiguration configurationForPublicKey(String publicKey) {
            if(vpnConfiguration.publicKey().equals(publicKey))
                return vpnConfiguration;
            else
                throw new IllegalArgumentException(MessageFormat.format("No configuration for public key {0}", publicKey));
        }

        @Override
        public void addScriptEnvironmentVariables(ActiveSession<?> connection, Map<String, String> env) {
            onAddScriptEnvironment.ifPresent(e -> e.accept(connection, env));
        }

        @Override
        public void close() {
            queue.shutdown();
        }
    }
}
