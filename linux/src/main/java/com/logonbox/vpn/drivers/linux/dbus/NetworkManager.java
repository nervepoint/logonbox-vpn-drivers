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
package com.logonbox.vpn.drivers.linux.dbus;

import org.freedesktop.dbus.DBusPath;
import org.freedesktop.dbus.Struct;
import org.freedesktop.dbus.annotations.DBusInterfaceName;
import org.freedesktop.dbus.annotations.Position;
import org.freedesktop.dbus.interfaces.DBusInterface;
import org.freedesktop.dbus.types.UInt32;
import org.freedesktop.dbus.types.Variant;

import java.util.Map;

import uk.co.bithatch.nativeimage.annotations.Proxy;
import uk.co.bithatch.nativeimage.annotations.Reflectable;
import uk.co.bithatch.nativeimage.annotations.TypeReflect;

@DBusInterfaceName("org.freedesktop.NetworkManager")
@Proxy
public interface NetworkManager extends DBusInterface {
	DBusPath GetDeviceByIpIface(String iface);

	@DBusInterfaceName("org.freedesktop.NetworkManager.Settings")
	@Proxy
	public interface Settings extends DBusInterface {
		DBusPath[] ListConnections();
		
		@DBusInterfaceName("org.freedesktop.NetworkManager.Settings.Connection")
		public interface Connection extends DBusInterface {
			Map<String, Map<String, Variant<?>>> GetSettings();
			void Update(Map<String, Map<String, Variant<?>>> settings);
			void Save();
		}
	}

	@Reflectable
    @TypeReflect(fields = true)
	public static class Ipv6Address extends Struct {
		@Position(0)
		private byte[] unknown1;
		@Position(1)
		private UInt32 unknown2;
		@Position(2)
		private byte[] unknown3;
		@Position(1)
		private UInt32 unknown4;
		
	}
}
