package com.logonbox.vpn.drivers.lib;

import java.io.Closeable;
import java.io.IOException;
import java.io.Reader;
import java.io.UncheckedIOException;
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

        private Optional<String> interfaceName = Optional.empty();
        private Optional<PlatformService<?>> platformService = Optional.empty();
        private Optional<VpnConfiguration> vpnConfiguration = Optional.empty();
        private Optional<VpnPeer> vpnPeer = Optional.empty();
        private Optional<SystemContext> systemContext = Optional.empty();
        private Optional<SystemConfiguration> systemConfiguration = Optional.empty();
        private Optional<BiConsumer<VpnAdapter, Map<String, String>>> onAddScriptEnvironment = Optional.empty();
        
        public Builder withPlatformService(PlatformService<?> platformService) {
            this.platformService = Optional.of(platformService);
            return this;
        }
        
        public Builder withSystemContext(SystemContext systemContext) {
            this.systemContext = Optional.of(systemContext);
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

        public Builder withInterfaceName(String interfaceName) {
            return withInterfaceName(Optional.of(interfaceName));
        }
        
        public Builder withInterfaceName(Optional<String> interfaceName) {
            this.interfaceName = interfaceName;
            return this;
        }
        
        public Builder onAddScriptEnvironment(BiConsumer<VpnAdapter, Map<String, String>> onAddScriptEnvironment) {
            this.onAddScriptEnvironment = Optional.of(onAddScriptEnvironment);
            return this;
        }
        
        public Vpn build() {
            return new Vpn(this);
        }
    }

    public static final Integer DEFAULT_PORT = 51820;
    
    private final PlatformService<? extends VpnAddress> platformService;
    private final Optional<BiConsumer<VpnAdapter, Map<String, String>>> onAddScriptEnvironment;
    private final VpnConfiguration cfg;
    private final Optional<VpnPeer> peer;
    private final Optional<String> interfaceName;

    private Optional<VpnAdapter> adapter = Optional.empty();

    
    private Vpn(Builder builder) {
        onAddScriptEnvironment = builder.onAddScriptEnvironment;
        interfaceName = builder.interfaceName;
        cfg = builder.vpnConfiguration.orElseThrow(() -> new IllegalStateException("No VPN configuration supplied."));
        
        /* If no specific peer, then try to find the first with an endpoint address and
         * assume that's the one to use.
         */
        peer = builder.vpnPeer.or(() -> {
            for(var p : cfg.peers()) {
                if(p.endpointAddress().isPresent())
                    return Optional.of(p);
            }
            return Optional.empty();
        }); 

        /* Either start a new session, or find an existing one */
        
        if (builder.platformService.isPresent()) {
            platformService = builder.platformService.get();
        } else {
            platformService = PlatformService.create(builder.systemContext.orElseGet(() -> new VpnSystemContext(builder.systemConfiguration)));
        }
        
        try {
			adapter = platformService.getByPublicKey(cfg.publicKey());
		} catch (IOException e) {
			throw new UncheckedIOException(e);
		}
    }
    
    public boolean started() {
        return adapter.isPresent();
    }
    
    public void open() throws IOException {
 /* Either start a new session, or find an existing one */
        if(adapter.isPresent())
            throw new IllegalStateException(MessageFormat.format("`{0}` already exists", adapter().address().shortName()));
        
        adapter = Optional.of(platformService.start(interfaceName, cfg, peer));
    }
    
    public Optional<String> interfaceName() {
        return interfaceName;
    }
    
    public PlatformService<?> platformService() {
        return platformService;
    }
    
    public VpnConfiguration configuration() {
        return cfg;
    }
    
    public VpnAdapter adapter() {
        return adapter.orElseThrow(() -> new IllegalStateException("Not started."));
    }
    
    public VpnInterfaceInformation information() throws IOException {
        return adapter().information();
    }

    @Override
    public void close() throws IOException {
        platformService.stop(cfg, adapter());
        if(platformService.context() instanceof VpnSystemContext)
            ((VpnSystemContext)platformService.context()).close();
    }
    
    class VpnSystemContext extends AbstractSystemContext implements Closeable {
        private final ScheduledExecutorService queue = Executors.newSingleThreadScheduledExecutor();
        private final SystemConfiguration configuration;
        
        VpnSystemContext(Optional<SystemConfiguration> configuration) {
            this.configuration = configuration.orElseGet(() -> SystemConfiguration.defaultConfiguration());
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
        public void addScriptEnvironmentVariables(VpnAdapter connection, Map<String, String> env) {
            onAddScriptEnvironment.ifPresent(e -> e.accept(connection, env));
        }

        @Override
        public void close() {
            queue.shutdown();
        }
    }
}
