using System;
using System.Runtime.InteropServices;
            
IntPtr Isolate = new IntPtr();
IntPtr Thread = new IntPtr();

if (LbvDll.GraalCreateIsolate(new IntPtr(0), out Isolate, out Thread) == 0)
{
    Console.WriteLine("Created Graal Isolate, Bringing Up VPN");
    
    String VpnConfig = @"[Interface]
PrivateKey = yLXzXXJ1pFHuykSb7U2tl5aaS3zpyP6OrfHeav4wlVk=
Address = 172.16.0.1
DNS = 127.0.0.53

[Peer]
PublicKey = K69dPM6jfmg4kbDIpQH7y/VSIMPFHQGzFJWYy9rY8h0=
Endpoint = 92.233.249.6:51820
PersistentKeepalive = 35
AllowedIPs = 127.0.0.53, 172.16.0.0/24, 192.168.91.0/24";

    IntPtr VpnConfigMem = Marshal.StringToHGlobalAnsi(VpnConfig);
    
    var VpnHandle = LbvDll.Up(Thread, VpnConfigMem, 0, 0);
    if (VpnHandle > 0)
    {
        Console.WriteLine("VPN is Up");
    }
    else
    {
        Console.WriteLine("Failed to bring VPN up");
    }
}
else
{
    Console.WriteLine("Failed to create Graal Isolate, VPN will not work");
}