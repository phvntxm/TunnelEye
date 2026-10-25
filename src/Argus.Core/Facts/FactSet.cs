// Copyright 2026 phvntxm
// SPDX-License-Identifier: Apache-2.0

using System.Collections.Generic;

namespace Argus.Core.Facts
{
    /// <summary>One fact item: plain values for conditions and where they came from in the snapshot.</summary>
    public sealed class FactItem
    {
        public FactItem(IDictionary<string, object> values, IEnumerable<string> evidence)
        {
            Values = values;
            Evidence = new List<string>(evidence ?? new string[0]);
        }

        public IDictionary<string, object> Values { get; }
        /// <summary>Paths in the snapshot, for example "routing.routes[3]".</summary>
        public IReadOnlyList<string> Evidence { get; }
    }

    /// <summary>
    /// A named fact: its items, or the reason it is unavailable (a module is
    /// missing, failed or skipped). Limitations name parts that could not be
    /// checked while the fact as a whole is available (D-014: "not checked"
    /// is never "all is well").
    /// </summary>
    public sealed class FactSet
    {
        private FactSet(string name, bool available, string unavailableReason)
        {
            Name = name;
            Available = available;
            UnavailableReason = unavailableReason;
            Items = new List<FactItem>();
            Limitations = new List<string>();
        }

        public string Name { get; }
        public bool Available { get; }
        public string UnavailableReason { get; }
        public List<FactItem> Items { get; }
        public List<string> Limitations { get; }

        public static FactSet Create(string name) => new FactSet(name, true, null);

        public static FactSet Unavailable(string name, string reason) => new FactSet(name, false, reason);
    }
}
