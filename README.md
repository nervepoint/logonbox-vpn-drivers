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
    <version>0.9.0-SNAPSHOT
</dependency>
    
```

Also part of this project, are the `remote` modules. These make it possible to access the low level API over D-Bus, in a separate process, or even potentially on a totally different machine (e.g. over SSH).

## Usage

### Creating a Wireguard Connection Using An INI file

The simplest usage is to create a working VPN tunnel given a standard Wireguard configuration file.

```java
/* TODO */ 
```

## Full Example Application And Tools

See [tools/README.md](tools/README.md) for a complete example application and usable tools.
 