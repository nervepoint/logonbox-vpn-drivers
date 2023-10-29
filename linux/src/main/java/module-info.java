/**
 * Copyright © 2023 LogonBox Limited (support@logonbox.com)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this
 * software and associated documentation files (the “Software”), to deal in the Software
 * without restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies
 * or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
import com.logonbox.vpn.drivers.lib.DNSProvider;
import com.logonbox.vpn.drivers.lib.PlatformServiceFactory;
import com.logonbox.vpn.drivers.linux.LinuxDNSProviderFactory;
import com.logonbox.vpn.drivers.linux.LinuxPlatformServiceFactory;

open module com.logonbox.vpn.drivers.os {
//    opens com.logonbox.vpn.drivers.linux.dbus to org.freedesktop.dbus;
    
    exports com.logonbox.vpn.drivers.linux;
    requires transitive com.logonbox.vpn.drivers.lib;
    
    requires com.github.jgonian.ipmath;
    requires org.slf4j;
    requires org.freedesktop.dbus;
    requires com.sshtools.liftlib;
    requires static uk.co.bithatch.nativeimage.annotations;
    
    provides PlatformServiceFactory with LinuxPlatformServiceFactory;
    provides DNSProvider.Factory with LinuxDNSProviderFactory;
}