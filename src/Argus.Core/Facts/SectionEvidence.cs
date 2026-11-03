// Copyright 2026 phvntxm
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Linq;
using Argus.Core.Json;
using Argus.Core.Snapshots;

namespace Argus.Core.Facts
{
    internal static class SectionEvidence
    {
        // Unknown errors conservatively invalidate negative conclusions. Unrelated,
        // known optional sources may fail without discarding positive evidence.
        internal static bool Complete(Snapshot snapshot, string module, string section, params string[] unrelatedSources)
        {
            var envelope = snapshot.Module(module);
            return envelope != null && envelope.IsUsable &&
                JsonValue.AsList(JsonValue.Get(envelope.Data, section)) != null &&
                envelope.Errors.All(e => unrelatedSources.Contains(e.Source, StringComparer.Ordinal) || Unrelated(module, section, e.Source));
        }

        private static bool Unrelated(string module, string section, string source)
        {
            if (module == "routing" && (section == "routes" || section == "interfaces"))
                return source != null && (source.StartsWith("Find-NetRoute ", StringComparison.Ordinal) || new[] {
                    "Get-NetRoute -PolicyStore PersistentStore", "Get-NetIPAddress", "IPEnableRouter", "bridge", "SharedAccess", "HNetCfg.HNetShare"
                }.Contains(source, StringComparer.Ordinal));
            if (module == "adapters" && section == "adapters")
                return new[] { "Get-NetAdapterBinding", "Get-NetAdapterAdvancedProperty", "Win32_PnPSignedDriver", "Get-PnpDevice", "pnputil /enum-drivers" }
                    .Contains(source, StringComparer.Ordinal);
            return false;
        }
    }
}
