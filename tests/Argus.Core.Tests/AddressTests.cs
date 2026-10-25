// Copyright 2026 phvntxm
// SPDX-License-Identifier: Apache-2.0

using Argus.Core.Facts;
using Xunit;

namespace Argus.Core.Tests
{
    /// <summary>Address classes match Get-AddressClass of the collectors (docs/schema/connections.md).</summary>
    public class AddressTests
    {
        [Theory]
        [InlineData("0.0.0.0", "unspecified")]
        [InlineData("::", "unspecified")]
        [InlineData("127.0.0.53", "loopback")]
        [InlineData("::1", "loopback")]
        [InlineData("10.1.2.3", "private")]
        [InlineData("172.16.0.1", "private")]
        [InlineData("172.32.0.1", "public")]
        [InlineData("192.168.1.1", "private")]
        [InlineData("fec0::1", "private")]
        [InlineData("100.100.100.100", "cgnat")]
        [InlineData("169.254.1.1", "linkLocal")]
        [InlineData("fe80::1%14", "linkLocal")]
        [InlineData("fd00::1", "uniqueLocal")]
        [InlineData("224.0.0.251", "multicast")]
        [InlineData("ff02::1", "multicast")]
        [InlineData("255.255.255.255", "broadcast")]
        [InlineData("::ffff:192.168.1.1", "private")]
        [InlineData("203.0.113.1", "public")]
        [InlineData("2001:db8::1", "public")]
        [InlineData("not an address", null)]
        [InlineData(null, null)]
        public void Classes(string address, string expected)
        {
            Assert.Equal(expected, Addresses.Class(address));
        }

        [Theory]
        [InlineData("fec0:0:0:ffff::1", true)]
        [InlineData("fec0:0:0:ffff::3", true)]
        [InlineData("FEC0:0:0:FFFF::2", true)]
        [InlineData("fec0:0:0:ffff::4", false)]
        [InlineData("fec0::1", false)]
        [InlineData("192.168.1.1", false)]
        public void Windows_dns_stubs(string address, bool expected)
        {
            Assert.Equal(expected, Addresses.IsWindowsDnsStub(address));
        }
    }
}
