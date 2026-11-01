// Copyright 2026 phvntxm
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using TunnelEye.App;
using Xunit;

namespace Argus.Core.Tests
{
    public class CollectionRunnerTests
    {
        [Fact]
        public async Task Uac_cancellation_falls_back_once_and_preserves_the_one_run_consent()
        {
            using (var fixture = new RunFixture())
            {
                var launcher = new FakeLauncher(info =>
                {
                    if (info.UseShellExecute) throw new Win32Exception(1223);
                    fixture.WriteSnapshot(false);
                    return new FakeProcess(0, 0);
                });
                var progress = new ProgressList();
                var result = await fixture.Runner(launcher).RunAsync(true, progress);
                Assert.False(result.WasElevated);
                Assert.Equal(2, launcher.Starts.Count);
                Assert.Equal("runas", launcher.Starts[0].Verb);
                Assert.True(launcher.Starts[0].UseShellExecute);
                Assert.False(launcher.Starts[1].UseShellExecute);
                Assert.True(launcher.Starts[1].CreateNoWindow);
                Assert.All(launcher.Starts, s => Assert.Contains(" -AllowExternal", s.Arguments));
                Assert.Contains(progress.Values, p => p.Status == "notElevated");
            }
        }

        [Fact]
        public async Task External_consent_is_never_remembered_between_runs()
        {
            using (var fixture = new RunFixture())
            {
                var launcher = new FakeLauncher(info => { fixture.WriteSnapshot(true); return new FakeProcess(0, 0); });
                var runner = fixture.Runner(launcher);
                var first = await runner.RunAsync(true, null);
                var second = await runner.RunAsync(false, null);
                Assert.True(first.WasElevated);
                Assert.True(second.WasElevated);
                Assert.NotEqual(first.SnapshotPath, second.SnapshotPath);
                Assert.Contains(" -AllowExternal", launcher.Starts[0].Arguments);
                Assert.DoesNotContain(" -AllowExternal", launcher.Starts[1].Arguments);
                Assert.Contains("-LaunchingUserSid \"S-1-0-0\"", launcher.Starts[0].Arguments);
                Assert.Contains("-TimeoutSec 120", launcher.Starts[0].Arguments);
                Assert.Contains("-File \"" + fixture.Script + "\"", launcher.Starts[0].Arguments);
                Assert.Equal(Path.GetDirectoryName(fixture.Script), launcher.Starts[0].WorkingDirectory);
            }
        }

        [Fact]
        public async Task Only_uac_cancellation_triggers_a_fallback()
        {
            using (var fixture = new RunFixture())
            {
                var launcher = new FakeLauncher(info => { throw new Win32Exception(5); });
                var error = await Assert.ThrowsAsync<CollectionRunException>(() => fixture.Runner(launcher).RunAsync(false, null));
                Assert.Equal(CollectionFailure.StartFailed, error.Reason);
                Assert.Single(launcher.Starts);
                Assert.DoesNotContain(fixture.Directory, error.Message);
            }
        }

        [Fact]
        public async Task Progress_handles_partial_utf8_lines_and_ignores_malformed_records()
        {
            using (var fixture = new RunFixture())
            {
                var complete = Encoding.UTF8.GetBytes("{\"event\":\"moduleEnd\",\"module\":\"тест\",\"index\":0,\"total\":1,\"status\":\"ok\"}\n");
                var split = Array.IndexOf(complete, (byte)0xD1) + 1;
                var progress = new ProgressList();
                var launcher = new FakeLauncher(info =>
                {
                    fixture.WriteSnapshot(true);
                    return new FakeProcess(0, 2, tick =>
                    {
                        var path = Path.Combine(fixture.LatestOutput, "progress.jsonl");
                        if (tick == 1)
                        {
                            File.WriteAllText(path, "{\"event\":\"start\",\"modules\":[\"wifi\"]}\n", new UTF8Encoding(false));
                            using (var f = new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.ReadWrite)) f.Write(complete, 0, split);
                        }
                        if (tick == 2)
                        {
                            using (var f = new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.ReadWrite)) f.Write(complete, split, complete.Length - split);
                            File.AppendAllText(path, "invalid record\n{\"event\":\"end\"}\n", new UTF8Encoding(false));
                        }
                    });
                });
                await fixture.Runner(launcher).RunAsync(false, progress);
                Assert.Single(progress.Values, p => p.Module == "тест" && p.Status == "ok");
                Assert.Equal(1, progress.Values.Last().Done);
                Assert.Equal(1, progress.Values.Last().Total);
                Assert.Equal("end", progress.Values.Last().Status);
            }
        }

        [Fact]
        public async Task A_locked_progress_file_does_not_lose_the_snapshot()
        {
            using (var fixture = new RunFixture())
            {
                FileStream held = null;
                var launcher = new FakeLauncher(info =>
                {
                    fixture.WriteSnapshot(true);
                    held = new FileStream(Path.Combine(fixture.LatestOutput, "progress.jsonl"), FileMode.Create, FileAccess.ReadWrite, FileShare.None);
                    return new FakeProcess(0, 1);
                });
                try { Assert.True((await fixture.Runner(launcher).RunAsync(false, null)).WasElevated); }
                finally { held?.Dispose(); }
            }
        }

        [Theory]
        [InlineData(7, false, false, CollectionFailure.ProcessFailed)]
        [InlineData(0, false, false, CollectionFailure.MissingSnapshot)]
        [InlineData(0, true, true, CollectionFailure.InvalidSnapshot)]
        public async Task A_failed_run_never_presents_a_successful_snapshot(int exitCode, bool createSnapshot, bool malformed, CollectionFailure reason)
        {
            using (var fixture = new RunFixture())
            {
                var launcher = new FakeLauncher(info =>
                {
                    if (createSnapshot) File.WriteAllText(Path.Combine(fixture.LatestOutput, "snapshot.json"), malformed ? "not json" : "{}");
                    return new FakeProcess(exitCode, 0);
                });
                var error = await Assert.ThrowsAsync<CollectionRunException>(() => fixture.Runner(launcher).RunAsync(false, null));
                Assert.Equal(reason, error.Reason);
            }
        }

        [Fact]
        public async Task Missing_collectors_do_not_launch_a_process()
        {
            using (var fixture = new RunFixture())
            {
                File.Delete(fixture.Script);
                var launcher = new FakeLauncher(info => new FakeProcess(0, 0));
                var error = await Assert.ThrowsAsync<CollectionRunException>(() => fixture.Runner(launcher).RunAsync(false, null));
                Assert.Equal(CollectionFailure.MissingCollectors, error.Reason);
                Assert.Empty(launcher.Starts);
            }
        }

        [Fact]
        public async Task A_slow_process_remains_owned_until_it_exits()
        {
            using (var fixture = new RunFixture())
            {
                var progress = new ProgressList();
                var process = new FakeProcess(0, 3);
                var launcher = new FakeLauncher(info => { fixture.WriteSnapshot(true); return process; });
                await fixture.Runner(launcher, TimeSpan.FromTicks(1)).RunAsync(false, progress);
                Assert.Contains(progress.Values, p => p.Status == "slow");
                Assert.True(process.Disposed);
                Assert.True(process.Exited);
            }
        }

        [Fact]
        public async Task A_runner_rejects_a_second_run_while_the_first_is_active()
        {
            using (var fixture = new RunFixture())
            {
                var process = new FakeProcess(0, 0) { Hold = true };
                var launcher = new FakeLauncher(info => { fixture.WriteSnapshot(true); return process; });
                var runner = fixture.Runner(launcher);
                var first = runner.RunAsync(false, null);
                await Assert.ThrowsAsync<InvalidOperationException>(() => runner.RunAsync(true, null));
                process.Hold = false;
                await first;
            }
        }

        private sealed class RunFixture : IDisposable
        {
            public string Directory { get; } = Path.Combine(Path.GetTempPath(), "TunnelEye-runner-example-" + Guid.NewGuid().ToString("N"));
            public string Script => Path.Combine(Directory, "example collectors", "Invoke-Snapshot.ps1");
            private string OutputRoot => Path.Combine(Directory, "example output");
            public string LatestOutput => System.IO.Directory.GetDirectories(OutputRoot).OrderBy(p => File.Exists(Path.Combine(p, "snapshot.json"))).ThenByDescending(p => System.IO.Directory.GetCreationTimeUtc(p)).First();
            public RunFixture()
            {
                System.IO.Directory.CreateDirectory(Path.GetDirectoryName(Script));
                File.WriteAllText(Script, "# This is never executed.");
            }
            public CollectionRunner Runner(FakeLauncher launcher, TimeSpan? slow = null) =>
                new CollectionRunner(Script, OutputRoot, launcher, "S-1-0-0", TimeSpan.FromMilliseconds(2), slow ?? TimeSpan.FromMinutes(1));
            public void WriteSnapshot(bool elevated) => File.WriteAllText(Path.Combine(LatestOutput, "snapshot.json"),
                "{\"schema\":\"tunneleye.snapshot/1\",\"host\":{\"elevated\":" + (elevated ? "true" : "false") + "},\"modules\":{}}");
            public void Dispose()
            {
                var absolute = Path.GetFullPath(Directory);
                var expectedPrefix = Path.Combine(Path.GetFullPath(Path.GetTempPath()), "TunnelEye-runner-example-");
                if (!absolute.StartsWith(expectedPrefix, StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("Unexpected test directory.");
                if (System.IO.Directory.Exists(absolute)) System.IO.Directory.Delete(absolute, true);
            }
        }

        private sealed class FakeLauncher : ICollectionProcessLauncher
        {
            private readonly Func<ProcessStartInfo, ICollectionProcess> start;
            public List<ProcessStartInfo> Starts { get; } = new List<ProcessStartInfo>();
            public FakeLauncher(Func<ProcessStartInfo, ICollectionProcess> start) { this.start = start; }
            public ICollectionProcess Start(ProcessStartInfo info) { Starts.Add(info); return start(info); }
        }

        private sealed class FakeProcess : ICollectionProcess
        {
            private readonly int exitCode;
            private readonly int ticksBeforeExit;
            private readonly Action<int> onTick;
            private int ticks;
            public volatile bool Hold;
            public bool Disposed { get; private set; }
            public bool Exited { get; private set; }
            public FakeProcess(int exitCode, int ticksBeforeExit, Action<int> onTick = null)
            { this.exitCode = exitCode; this.ticksBeforeExit = ticksBeforeExit; this.onTick = onTick; }
            public bool HasExited
            {
                get
                {
                    if (Hold) return false;
                    ticks++;
                    onTick?.Invoke(ticks);
                    Exited = ticks > ticksBeforeExit;
                    return Exited;
                }
            }
            public int ExitCode => exitCode;
            public void Dispose() { Disposed = true; }
        }

        private sealed class ProgressList : IProgress<CollectionProgress>
        {
            public List<CollectionProgress> Values { get; } = new List<CollectionProgress>();
            public void Report(CollectionProgress value) { Values.Add(value); }
        }
    }
}
