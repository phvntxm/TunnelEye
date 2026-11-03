// Copyright 2026 phvntxm
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Argus.Core.Json;
using Argus.Core.Snapshots;

namespace TunnelEye.App
{
    public sealed class CollectionProgress
    {
        public CollectionProgress(int done, int total, string module, string status, bool? elevated = null)
        { Done = done; Total = total; Module = module; Status = status; Elevated = elevated; }
        public bool? Elevated { get; }
        public int Done { get; }
        public int Total { get; }
        public string Module { get; }
        public string Status { get; }
    }

    public sealed class CollectionRunResult
    {
        public CollectionRunResult(string snapshotPath, bool wasElevated)
        { SnapshotPath = snapshotPath; WasElevated = wasElevated; }
        public string SnapshotPath { get; }
        public bool WasElevated { get; }
    }

    public enum CollectionFailure { MissingCollectors, StartFailed, ProcessFailed, MissingSnapshot, InvalidSnapshot }

    /// <summary>Safe machine-readable reason; the window supplies localized text.</summary>
    public sealed class CollectionRunException : Exception
    {
        public CollectionRunException(CollectionFailure reason, int? exitCode = null) : base(reason.ToString()) { Reason = reason; ExitCode = exitCode; }
        public CollectionFailure Reason { get; }
        public int? ExitCode { get; }
    }

    /// <summary>Injectable process boundary: tests never run UAC or real collectors.</summary>
    public interface ICollectionProcess : IDisposable
    {
        bool HasExited { get; }
        int ExitCode { get; }
    }

    public interface ICollectionProcessLauncher
    {
        ICollectionProcess Start(ProcessStartInfo startInfo);
    }

    /// <summary>
    /// Owns one collector run. The UI must prevent closing while RunAsync is
    /// active: a normal user cannot safely terminate an elevated process tree.
    /// The orchestrator itself bounds each collector to 120 seconds. A slow run
    /// is reported, never abandoned or represented as falsely cancelled.
    /// </summary>
    public sealed class CollectionRunner
    {
        private readonly string scriptPath;
        private readonly string outputRoot;
        private readonly string launchingSid;
        private readonly ICollectionProcessLauncher launcher;
        private readonly TimeSpan pollInterval;
        private readonly TimeSpan slowAfter;
        private int running;

        public CollectionRunner() : this(
            Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "collectors", "Invoke-Snapshot.ps1"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "TunnelEye", "snapshots"),
            new NativeProcessLauncher()) { }

        public CollectionRunner(string collectorScriptPath, string outputDirectory, ICollectionProcessLauncher processLauncher,
            string launchingUserSid = null, TimeSpan? pollingInterval = null, TimeSpan? slowRunAfter = null)
        {
            if (collectorScriptPath == null) throw new ArgumentNullException(nameof(collectorScriptPath));
            if (outputDirectory == null) throw new ArgumentNullException(nameof(outputDirectory));
            scriptPath = Path.GetFullPath(collectorScriptPath);
            outputRoot = Path.GetFullPath(outputDirectory);
            launcher = processLauncher ?? throw new ArgumentNullException(nameof(processLauncher));
            launchingSid = launchingUserSid ?? ReadCurrentSid();
            pollInterval = pollingInterval ?? TimeSpan.FromMilliseconds(300);
            slowAfter = slowRunAfter ?? TimeSpan.FromMinutes(30);
            if (pollInterval <= TimeSpan.Zero || slowAfter <= TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(pollingInterval));
        }

        private static string ReadCurrentSid()
        {
            using (var identity = WindowsIdentity.GetCurrent()) return identity.User.Value;
        }

        public Task<CollectionRunResult> RunAsync(bool allowExternal, IProgress<CollectionProgress> progress)
        {
            if (Interlocked.CompareExchange(ref running, 1, 0) != 0)
                throw new InvalidOperationException("CollectionAlreadyRunning");
            // Process.Start with runas waits for UAC. Keep that wait off the UI thread.
            return Task.Run(async () =>
            {
                try { return await RunCoreAsync(allowExternal, progress).ConfigureAwait(false); }
                finally { Interlocked.Exchange(ref running, 0); }
            });
        }

        private async Task<CollectionRunResult> RunCoreAsync(bool allowExternal, IProgress<CollectionProgress> progress)
        {
            if (!File.Exists(scriptPath)) throw new CollectionRunException(CollectionFailure.MissingCollectors);
            var output = Path.Combine(outputRoot, DateTime.UtcNow.ToString("yyyyMMdd-HHmmss") + "-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(output);
            ICollectionProcess process;
            try
            {
                try { process = launcher.Start(CreateStartInfo(output, allowExternal, true)); }
                catch (Win32Exception e) when (e.NativeErrorCode == 1223)
                {
                    progress?.Report(new CollectionProgress(0, 13, null, "notElevated"));
                    process = launcher.Start(CreateStartInfo(output, allowExternal, false));
                }
            }
            catch (Exception e) when (e is Win32Exception || e is InvalidOperationException)
            { throw new CollectionRunException(CollectionFailure.StartFailed); }
            if (process == null) throw new CollectionRunException(CollectionFailure.StartFailed);
            using (process)
            {
                var reader = new ProgressTail(Path.Combine(output, "progress.jsonl"));
                var watch = Stopwatch.StartNew();
                bool warned = false;
                while (!process.HasExited)
                {
                    reader.Poll(progress);
                    if (!warned && watch.Elapsed > slowAfter)
                    {
                        warned = true;
                        progress?.Report(new CollectionProgress(reader.Done, reader.Total, null, "slow"));
                    }
                    // Keep ownership while an elevated process is alive. Killing just
                    // the parent would orphan its collectors and is deliberately avoided.
                    await Task.Delay(pollInterval).ConfigureAwait(false);
                }
                reader.Poll(progress);
                if (process.ExitCode != 0) throw new CollectionRunException(CollectionFailure.ProcessFailed, process.ExitCode);
            }
            var snapshotPath = Path.Combine(output, "snapshot.json");
            if (!File.Exists(snapshotPath)) throw new CollectionRunException(CollectionFailure.MissingSnapshot);
            try
            {
                var snapshot = Snapshot.Load(snapshotPath);
                return new CollectionRunResult(snapshotPath, snapshot.Elevated == true);
            }
            catch (Exception e) when (e is IOException || e is UnauthorizedAccessException || e is ArgumentException || e is SnapshotFormatException)
            { throw new CollectionRunException(CollectionFailure.InvalidSnapshot); }
        }

        private ProcessStartInfo CreateStartInfo(string output, bool allowExternal, bool elevate)
        {
            // Process scope only; do not change CurrentUser/LocalMachine policy or unblock files.
            var arguments = "-NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -File " + Quote(scriptPath) + " -OutputDirectory " + Quote(output)
                + " -LaunchingUserSid " + Quote(launchingSid) + " -TimeoutSec 120";
            if (allowExternal) arguments += " -AllowExternal";
            var system = Environment.GetFolderPath(Environment.SpecialFolder.System);
            return new ProcessStartInfo
            {
                FileName = Path.Combine(system, "WindowsPowerShell", "v1.0", "powershell.exe"),
                Arguments = arguments,
                WorkingDirectory = Path.GetDirectoryName(scriptPath),
                UseShellExecute = elevate,
                Verb = elevate ? "runas" : "",
                WindowStyle = ProcessWindowStyle.Hidden,
                CreateNoWindow = true,
            };
        }

        // Windows command-line quoting. No shell or PowerShell expression is built.
        private static string Quote(string value)
        {
            var b = new StringBuilder("\"");
            int slashes = 0;
            foreach (var c in value)
            {
                if (c == '\\') { slashes++; continue; }
                if (c == '"') { b.Append('\\', slashes * 2 + 1); b.Append(c); slashes = 0; continue; }
                b.Append('\\', slashes); slashes = 0; b.Append(c);
            }
            b.Append('\\', slashes * 2); b.Append('"');
            return b.ToString();
        }

        private sealed class ProgressTail
        {
            private readonly string path;
            private long offset;
            private Decoder decoder = Encoding.UTF8.GetDecoder();
            private string pending = "";
            public int Done { get; private set; }
            public int Total { get; private set; } = 13;
            public ProgressTail(string path) { this.path = path; }

            public void Poll(IProgress<CollectionProgress> progress)
            {
                try
                {
                    using (var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                    {
                        if (file.Length < offset) { offset = 0; pending = ""; decoder = Encoding.UTF8.GetDecoder(); }
                        file.Position = offset;
                        var bytes = new byte[8192];
                        var chars = new char[Encoding.UTF8.GetMaxCharCount(bytes.Length)];
                        int count;
                        while ((count = file.Read(bytes, 0, bytes.Length)) > 0)
                        {
                            offset += count;
                            pending += new string(chars, 0, decoder.GetChars(bytes, 0, count, chars, 0, false));
                            int newline;
                            while ((newline = pending.IndexOf('\n')) >= 0)
                            {
                                var line = pending.Substring(0, newline).TrimEnd('\r');
                                pending = pending.Substring(newline + 1);
                                Parse(line, progress);
                            }
                            if (pending.Length > 65536) pending = "";
                        }
                    }
                }
                catch (IOException) { }
                catch (UnauthorizedAccessException) { }
            }

            private void Parse(string line, IProgress<CollectionProgress> progress)
            {
                try
                {
                    var tree = JsonValue.Parse(line);
                    var kind = JsonValue.AsString(JsonValue.Get(tree, "event"));
                    var total = JsonValue.AsInt(JsonValue.Get(tree, "total"));
                    if (total.HasValue && total > 0 && total <= 1000) Total = total.Value;
                    if (kind == "start")
                    {
                        var modules = JsonValue.GetList(tree, "modules");
                        if (modules.Count > 0 && modules.Count <= 1000) Total = modules.Count;
                        progress?.Report(new CollectionProgress(0, Total, null, "start", JsonValue.AsBool(JsonValue.Get(tree, "elevated"))));
                    }
                    else if (kind == "moduleStart" || kind == "moduleEnd")
                    {
                        var index = JsonValue.AsInt(JsonValue.Get(tree, "index"));
                        if (!index.HasValue || index < 0 || index >= Total) return;
                        Done = Math.Max(Done, Math.Min(Total, index.Value + (kind == "moduleEnd" ? 1 : 0)));
                        progress?.Report(new CollectionProgress(Done, Total, JsonValue.AsString(JsonValue.Get(tree, "module")),
                            kind == "moduleEnd" ? JsonValue.AsString(JsonValue.Get(tree, "status")) : "running"));
                    }
                    else if (kind == "end")
                    {
                        Done = Total;
                        progress?.Report(new CollectionProgress(Done, Total, null, "end"));
                    }
                }
                catch (ArgumentException) { }
                catch (InvalidOperationException) { }
            }
        }

        private sealed class NativeProcessLauncher : ICollectionProcessLauncher
        {
            public ICollectionProcess Start(ProcessStartInfo startInfo) => new NativeProcess(Process.Start(startInfo));
        }

        private sealed class NativeProcess : ICollectionProcess
        {
            private readonly Process process;
            public NativeProcess(Process process) { this.process = process ?? throw new InvalidOperationException("NoProcess"); }
            public bool HasExited => process.HasExited;
            public int ExitCode => process.ExitCode;
            public void Dispose() { process.Dispose(); }
        }
    }
}
