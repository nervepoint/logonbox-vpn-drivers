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
import com.logonbox.vpn.drivers.lib.util.Keys;
import com.logonbox.vpn.drivers.lib.util.impl.BasicKeys;
import com.logonbox.vpn.drivers.lib.util.impl.JCEKeys;
import com.logonbox.vpn.drivers.lib.util.impl.WhisperKeys;

open module com.logonbox.vpn.drivers.lib {
    exports com.logonbox.vpn.drivers.lib;
    exports com.logonbox.vpn.drivers.lib.util;
    requires transitive org.slf4j;
    requires com.github.jgonian.ipmath;
    requires transitive com.sshtools.liftlib;
    requires transitive com.sshtools.jini;
    requires static uk.co.bithatch.nativeimage.annotations;
	requires transitive java.prefs;
	requires curve25519.java; // boo
    
    uses PlatformServiceFactory;
    uses DNSProvider.Factory;
    
    uses Keys.KeyPairProvider;

	provides Keys.KeyPairProvider with WhisperKeys/* , BasicKeys, JCEKeys */;
}