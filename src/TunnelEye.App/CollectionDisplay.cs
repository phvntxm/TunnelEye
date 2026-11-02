// Copyright 2026 phvntxm
// SPDX-License-Identifier: Apache-2.0
using System;
using System.Globalization;
using Argus.Core.Reports;

namespace TunnelEye.App
{
    /// <summary>Only collector events may advance measured progress.</summary>
    public sealed class CollectionDisplay
    {
        public int Done { get; private set; }
        public int? Total { get; private set; }
        public string Module { get; private set; }
        public bool? Elevated { get; private set; }
        public bool Ended { get; private set; }
        public bool Failed { get; private set; }
        public bool Slow { get; private set; }
        public bool Analyzing { get; private set; }
        public bool ModuleFailed { get; private set; }
        public int ActiveEye { get; private set; }
        public bool HasEvents { get; private set; }
        public bool CanAnimate => HasEvents && !Ended && !Failed && !Analyzing;
        public void Accept(CollectionProgress progress)
        {
            if (progress == null || Ended || Failed || Analyzing) return;
            if (progress.Status == "notElevated") { Elevated = false; return; }
            if (progress.Status == "slow") { Slow = true; return; }
            if (Total.HasValue && progress.Total > 0 && progress.Total != Total.Value) return;
            HasEvents = true;
            if (progress.Elevated.HasValue) Elevated = progress.Elevated;
            if (progress.Total > 0 && progress.Total <= 1000)
            {
                Total = progress.Total;
                var next = Math.Max(Done, Math.Min(progress.Total, Math.Max(0, progress.Done)));
                if (next > Done && progress.Status != "running") ActiveEye = (ActiveEye + 1) % 5;
                Done = next;
            }
            if (!string.IsNullOrEmpty(progress.Module)) Module = progress.Module;
            ModuleFailed = progress.Status == "failed";
            if (progress.Status == "end") Ended = true;
        }
        public void Analyze() { Analyzing = true; }
        public void Fail() { Failed = true; }
        public string Current(string language)
        {
            var key = Failed ? "CollectionStopped" : Analyzing || Ended ? "Analyzing" :
                !HasEvents ? "AwaitingCollector" : string.IsNullOrEmpty(Module) ? "AwaitingModule" : "CheckingModule";
            return string.Format(CultureInfo.GetCultureInfo(language), AppStrings.Get(key, language),
                string.IsNullOrEmpty(Module) ? AppStrings.Get("AwaitingModule", language) : ReportText.Get("Module_" + Module, language));
        }
        public string Count(string language) => Total.HasValue ? string.Format(CultureInfo.GetCultureInfo(language),
            AppStrings.Get("CompletedModules", language), Done, Total.Value) : AppStrings.Get("UnknownProgress", language);
        public string Mode(string language) => AppStrings.Get(Elevated == true ? "CollectionAdmin" : Elevated == false ? "CollectionLimited" : "CollectionUnknownRights", language);
        public string Note(string language) => AppStrings.Get(Failed ? "CollectionFailureNote" : Slow ? "SlowCollection" :
            ModuleFailed ? "ModuleFailedContinuing" : !HasEvents ? "AwaitingCollectorNote" : "AnimationProgressNote", language);
    }
}
