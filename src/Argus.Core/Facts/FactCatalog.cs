// Copyright 2026 phvntxm
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Collections.Generic;
using Argus.Core.Snapshots;

namespace Argus.Core.Facts
{
    /// <summary>Builds one named fact from a snapshot; may use other facts through the context.</summary>
    public interface IFactProvider
    {
        string Name { get; }
        FactSet Build(FactContext context);
    }

    /// <summary>Snapshot plus the facts built so far: providers depend on each other without rebuilding.</summary>
    public sealed class FactContext
    {
        private readonly Dictionary<string, FactSet> _built = new Dictionary<string, FactSet>(StringComparer.Ordinal);
        private readonly FactCatalog _catalog;
        private readonly HashSet<string> _building = new HashSet<string>(StringComparer.Ordinal);

        internal FactContext(Snapshot snapshot, FactCatalog catalog)
        {
            Snapshot = snapshot;
            _catalog = catalog;
        }

        public Snapshot Snapshot { get; }

        /// <summary>Errors of fact providers: a failing fact is unavailable, the others still work.</summary>
        public List<string> Errors { get; } = new List<string>();

        /// <summary>The fact, built on first use; an unknown name gives an unavailable fact.</summary>
        public FactSet Get(string name)
        {
            FactSet fact;
            if (_built.TryGetValue(name, out fact)) return fact;
            var provider = _catalog.Find(name);
            if (provider == null) return FactSet.Unavailable(name, "unknown-fact");
            if (!_building.Add(name)) throw new InvalidOperationException("Fact dependency cycle at '" + name + "'.");
            try { fact = provider.Build(this); }
            catch (Exception e) when (!(e is InvalidOperationException && e.Message.StartsWith("Fact dependency cycle", StringComparison.Ordinal)))
            {
                // Like a failing collector in stage 1: this fact is lost, the analysis goes on.
                Errors.Add("fact " + name + ": " + e.GetType().Name + ": " + e.Message);
                fact = FactSet.Unavailable(name, "fact-error:" + e.GetType().Name);
            }
            finally { _building.Remove(name); }
            _built[name] = fact;
            return fact;
        }

        /// <summary>
        /// Data of a module, or null with the reason: module-missing,
        /// module-failed or module-skipped (with the module name).
        /// </summary>
        public IDictionary<string, object> ModuleData(string module, out string reason)
        {
            reason = null;
            var envelope = Snapshot.Module(module);
            if (envelope == null) { reason = "module-missing:" + module; return null; }
            if (!envelope.IsUsable) { reason = "module-" + (envelope.Status ?? "unknown") + ":" + module; return null; }
            return envelope.Data;
        }
    }

    /// <summary>All known facts. The set is versioned: a change of fact names or fields is a new version.</summary>
    public sealed class FactCatalog
    {
        public const string Version = "facts/1";

        private readonly Dictionary<string, IFactProvider> _providers = new Dictionary<string, IFactProvider>(StringComparer.Ordinal);

        public FactCatalog(IEnumerable<IFactProvider> providers)
        {
            foreach (var p in providers) _providers[p.Name] = p;
        }

        public static FactCatalog CreateDefault()
        {
            return new FactCatalog(new IFactProvider[]
            {
                new AdapterFacts(),
                new RouteSummaryFacts(),
                new ProxyFacts(),
                new LeftoverFacts(),
                new TunnelFacts(),
                new TunnelCoverageFacts(),
                new DnsServerFacts(),
                new HostsFacts(),
                new BridgeFacts(),
                new ConnectionSharingFacts(),
                new TraceFacts(),
                new DnsAnswerFacts(),
                new SnapshotInfoFacts(),
                new WifiFacts(),
                new ExposedPortFacts(),
                new WfpFacts(),
                new InterfaceMtuFacts(),
                new AdapterPropertyFacts(),
                new MissingFileFacts(),
            });
        }

        public IEnumerable<string> Names => _providers.Keys;

        public bool Contains(string name) => _providers.ContainsKey(name);

        internal IFactProvider Find(string name)
        {
            IFactProvider provider;
            return _providers.TryGetValue(name, out provider) ? provider : null;
        }

        public FactContext CreateContext(Snapshot snapshot) => new FactContext(snapshot, this);
    }
}
