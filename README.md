# logonbox-vpn-drivers

These modules provide a common Java interface to configure and maintain a [Wireguard](https://www.wireguard.com/)
VPN.

It currently supports 3 operating systems.

 * Windows
 * Linux
 * Mac OS
 
Used by LogonBox's VPN server and client products, the library deals with all the OS specific
configuration, allowing consumers of the library to simply supply the base wireguard configuration
and request a virtual network.

 * Create and configure virtual adapter.
 * Assign IP addresses and configure routes.
 * Configure DNS.
 * Allow management and querying of active sessions.
 * If appropriate, needed system services are created, managed and removed when finished with.  
 
 
## Installation

You just need to add the appropriate driver library, and that will pull in required 
dependencies (it is suggested you use profiles to activate the appropriate dependency).

 * `logonbox-vpn-linux` for Linux (all architectures)
 * `logonbox-vpn-macos` for Mac OS (all architectures)
 * `logonbox-vpn-windows` for Windows (all architectures)

For example,

```xml
<dependency>
    <groupId>com.logonbox</groupId>
    <artifactId>logonbox-vpn-linux</artifactId>
    <version>1.0.0</version>
</dependency>
    
```

Also part of this project, are the `remote` modules. These make it possible to access the low level API over D-Bus, in a separate process, or even potentially on a totally different machine (e.g. over SSH).

## Usage


### Creating a Wireguard Connection Using An INI file

The simplest usage is to create a working VPN tunnel given a standard Wireguard configuration file using `Vpn.Builder`. 

```java
// Start and stop the VPN after a minute
try(var vpn = new Vpn.Builder().
	withVpnConfiguration("""
	[Interface]
	PrivateKey=83aPzAqghs3wqssdh5as1DAgi77TWFygmkwqRdGAzUQ=
	Address=172.16.0.1
	DNS=192.168.123.1, mycorp.lan
	
	[Peer]
	PublicKey=YUJ8nEyJi1BU3EtFOFXtP+yJZZF9IiN/F2p6/m8x90E=
	Endpoint=1.2.3.4:51820
	AllowedIPs=172.16.0.0/16, 192.168.123.0/24, 192.168.122.0/24, 172.17.0.0/16
	PersistentKeepalive=35
			""").
	build()) {
	
	vpn.open();
	
	Thread.sleep(Duration.ofMinutes(1).toMillis());
}
		
```

or you could retrieve the configuration over HTTP ...

```java
// Make a builder
var bldr = new Vpn.Builder();

// We are accessing over HTTPS, and may need to authentication
HttpURLConnection.setDefaultAllowUserInteraction(true);
Authenticator.setDefault(new Authenticator() {

	@Override
	protected PasswordAuthentication getPasswordAuthentication() {
		return new PasswordAuthentication("joe.b", "Password123?".toCharArray());
	}
	
});

// Get some config
try(var in = new URL("https://myawesomecompany.com/get-vpn/basic/admin.wg.conf").openStream()) {
	bldr.withVpnConfiguration(new InputStreamReader(in));
}

// Start and stop the VPN after one minute
try(var vpn = bldr.build()) {
	
	vpn.open();

	// Wait a minute
	Thread.sleep(Duration.ofMinutes(1).toMillis());
}
```

### Creating a Wireguard Connection With Java

You can use use builder to create a configuration, including key generation. 

```java
var cfg = new VpnConfiguration.Builder().
	withAddresses("172.16.0.1").
	withDns("192.168.123.1", "mycorp.lan").
	withPeers(new VpnPeer.Builder().
		withPublicKey("YUJ8nEyJi1BU3EtFOFXtP+yJZZF9IiN/F2p6/m8x90E=").
		withEndpoint("1.2.3.4:51820").
		withAllowedIps("172.16.0.0/16", "192.168.123.0/24", "192.168.122.0/24", "172.17.0.0/16").
		build()).
	build();

System.out.format("""
	Your generated public key is: %s
	
	This must be added to a [Peer] configuration on %s along with your requested IP
	address %s. For example,
	
	[Peer]
	PublicKey=%s
	AllowedIPs=%s
	""", 
	cfg.publicKey(), 
	cfg.peers().get(0).endpointAddress().orElse("Unknown"),
 	String.join(", ", cfg.addresses()),
 	cfg.publicKey(),
 	String.join(", ", cfg.addresses()));

// Start and stop the VPN after one minute
try(var vpn = new Vpn.Builder().
	withVpnConfiguration(cfg).
	build()) {
	
	vpn.open();
	
	Thread.sleep(Duration.ofMinutes(1).toMillis());
}
```

## Full Example Application And Tools

See [tools/README.md](tools/README.md) for a complete example application and usable tools.

## Credits

See [WIREGUARD-LICENSE.txt](WIREGUARD-LICENSE.txt) and [WireGuardNT-LICENSE.txt] for more information on included Wireguard commponents.
