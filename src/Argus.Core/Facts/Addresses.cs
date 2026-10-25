// Copyright 2026 phvntxm
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Net;
using System.Net.Sockets;

namespace Argus.Core.Facts
{
    /// <summary>
    /// Address helpers shared by facts. Classes are the same as
    /// Get-AddressClass of the collectors (docs/schema/connections.md).
    /// </summary>
    internal static class Addresses
    {
        /// <summary>
        /// unspecified, loopback, private, cgnat, linkLocal, uniqueLocal,
        /// multicast, broadcast or public; null if the text is not an address.
        /// An IPv6 zone (%14) is ignored; IPv4-mapped IPv6 counts as IPv4.
        /// </summary>
        internal static string Class(string address)
        {
            IPAddress ip;
            if (!IPAddress.TryParse(StripZone(address) ?? "", out ip)) return null;
            if (ip.AddressFamily == AddressFamily.InterNetworkV6 && ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
            var b = ip.GetAddressBytes();
            if (ip.AddressFamily == AddressFamily.InterNetwork)
            {
                if (b[0] == 0 && b[1] == 0 && b[2] == 0 && b[3] == 0) return "unspecified";
                if (b[0] == 127) return "loopback";
                if (b[0] == 10 || (b[0] == 172 && b[1] >= 16 && b[1] <= 31) || (b[0] == 192 && b[1] == 168)) return "private";
                if (b[0] == 100 && b[1] >= 64 && b[1] <= 127) return "cgnat";
                if (b[0] == 169 && b[1] == 254) return "linkLocal";
                if (b[0] >= 224 && b[0] <= 239) return "multicast";
                if (b[0] == 255 && b[1] == 255 && b[2] == 255 && b[3] == 255) return "broadcast";
                return "public";
            }
            if (ip.Equals(IPAddress.IPv6Any)) return "unspecified";
            if (ip.Equals(IPAddress.IPv6Loopback)) return "loopback";
            if (b[0] == 0xfe && (b[1] & 0xc0) == 0xc0) return "private";
            if (b[0] == 0xfe && (b[1] & 0xc0) == 0x80) return "linkLocal";
            if ((b[0] & 0xfe) == 0xfc) return "uniqueLocal";
            if (b[0] == 0xff) return "multicast";
            return "public";
        }

        /// <summary>The address without an IPv6 zone: fe80::1%14 -> fe80::1.</summary>
        internal static string StripZone(string address)
        {
            if (address == null) return null;
            var zone = address.IndexOf('%');
            return zone >= 0 ? address.Substring(0, zone) : address;
        }

        /// <summary>
        /// fec0:0:0:ffff::1..3: Windows reports them for interfaces without an
        /// IPv6 DNS server; they are not servers (D-007).
        /// </summary>
        internal static bool IsWindowsDnsStub(string address)
        {
            IPAddress ip;
            if (!IPAddress.TryParse(StripZone(address) ?? "", out ip) || ip.AddressFamily != AddressFamily.InterNetworkV6) return false;
            var b = ip.GetAddressBytes();
            for (var i = 0; i < 15; i++)
            {
                var expected = i == 0 ? 0xfe : i == 1 ? 0xc0 : (i == 6 || i == 7) ? 0xff : 0;
                if (b[i] != expected) return false;
            }
            return b[15] >= 1 && b[15] <= 3;
        }

        /// <summary>Equality of two addresses as text, ignoring case and the IPv6 zone.</summary>
        internal static bool Same(string a, string b)
        {
            return string.Equals(StripZone(a), StripZone(b), StringComparison.OrdinalIgnoreCase);
        }
    }
}
