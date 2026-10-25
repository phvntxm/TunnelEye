// Copyright 2026 phvntxm
// SPDX-License-Identifier: Apache-2.0

using System.IO;
using System.Linq;
using System.Text;
using Argus.Core.Json;
using Argus.Core.Snapshots;
using Xunit;

namespace Argus.Core.Tests
{
    public class JsonTests
    {
        [Fact]
        public void Reads_a_snapshot_larger_than_the_default_serializer_limit()
        {
            // JavaScriptSerializer stops at 2,097,152 characters by default.
            var clean = File.ReadAllText(Path.Combine(TestData.SnapshotsDir, "clean.json"), Encoding.UTF8);
            var filler = new StringBuilder();
            for (var i = 0; i < 40000; i++) filler.Append(i == 0 ? "" : ",").Append("{\"logName\":\"System\",\"provider\":\"Tcpip\",\"eventId\":4207,\"count\":1}");
            var big = clean.Replace("\"modules\": {", "\"padding\": [" + filler + "], \"modules\": {");
            Assert.True(big.Length > 2200000);
            var snapshot = Snapshot.Parse(big);
            Assert.Equal("00000000-0000-4000-8000-000000000001", snapshot.SnapshotId);
        }

        [Fact]
        public void Reads_deep_nesting_beyond_the_default_recursion_limit()
        {
            var json = new string('[', 150) + new string(']', 150);
            Assert.NotNull(JsonValue.Parse(json));
        }

        [Fact]
        public void Normalizes_numbers_of_different_types()
        {
            var tree = JsonValue.Parse("{\"a\":1,\"b\":1.0,\"c\":10000000000,\"d\":2.5}");
            Assert.Equal(JsonValue.AsDecimal(JsonValue.Get(tree, "a")), JsonValue.AsDecimal(JsonValue.Get(tree, "b")));
            Assert.Equal(10000000000m, JsonValue.AsDecimal(JsonValue.Get(tree, "c")));
            Assert.Null(JsonValue.AsInt(JsonValue.Get(tree, "d")));
            Assert.Equal(1, JsonValue.AsInt(JsonValue.Get(tree, "b")));
        }

        [Fact]
        public void Distinguishes_a_missing_path_from_a_null_value()
        {
            var tree = JsonValue.Parse("{\"a\":{\"b\":null,\"list\":[{\"x\":1}]}}");
            object value;
            Assert.True(JsonValue.TryGetPath(tree, "a.b", out value));
            Assert.Null(value);
            Assert.False(JsonValue.TryGetPath(tree, "a.c", out value));
            Assert.True(JsonValue.TryGetPath(tree, "a.list[0].x", out value));
            Assert.Equal(1, value);
            Assert.False(JsonValue.TryGetPath(tree, "a.list[1].x", out value));
        }

        [Fact]
        public void Rejects_unknown_snapshot_and_module_schemas()
        {
            Assert.Throws<SnapshotFormatException>(() => Snapshot.Parse("{\"schema\":\"tunneleye.snapshot/2\"}"));
            Assert.Throws<SnapshotFormatException>(() => Snapshot.Parse("{\"schema\":\"tunneleye.snapshot/1\",\"modules\":{\"x\":{\"schema\":\"other\"}}}"));
        }

        [Fact]
        public void Treats_failed_and_skipped_modules_as_unusable()
        {
            var snapshot = TestData.LoadSnapshot("routing-failed");
            Assert.False(snapshot.Module("routing").IsUsable);
            Assert.True(snapshot.Module("adapters").IsUsable);
            Assert.Null(snapshot.Module("hardware"));
            Assert.Contains(snapshot.Modules, m => m.Name == "vpn");
            Assert.Equal(6, snapshot.Modules.Count());
        }
    }
}
