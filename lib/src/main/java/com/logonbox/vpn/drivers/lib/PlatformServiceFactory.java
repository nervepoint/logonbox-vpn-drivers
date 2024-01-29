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
package com.logonbox.vpn.drivers.lib;

import java.util.ServiceLoader;

public interface PlatformServiceFactory {
    
    public static PlatformServiceFactory get() {
        return get(PlatformServiceFactory.class.getClassLoader());
    }
    
	public static PlatformServiceFactory get(ClassLoader clzloader) {
		return ServiceLoader.load(PlatformServiceFactory.class, clzloader).findFirst().filter(p -> p.isSupported())
				.orElseThrow(() -> new UnsupportedOperationException(String.format(
						"%s not currently supported. There are no platform extensions installed, you may be missing libraries. Discovered extensions are .. %s",
						System.getProperty("os.name"),
						String.join(System.lineSeparator(),
								ServiceLoader.load(PlatformServiceFactory.class, clzloader).stream()
										.map(f -> f.type().getName() + " [" + (f.get().isSupported() ? "X" : ".") + "]")
										.toList()))));

	}
    
    boolean isSupported();

	PlatformService<? extends VpnAddress> createPlatformService(SystemContext context);
}
