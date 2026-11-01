// Copyright 2026 phvntxm
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Globalization;
using System.Resources;
using System.Windows;

namespace TunnelEye.App
{
    public static class AppStrings
    {
        private static readonly ResourceManager Resources = new ResourceManager("TunnelEye.App.Strings", typeof(AppStrings).Assembly);
        public static string Data(string value, string language) => Resources.GetString("Data_" + value, CultureInfo.GetCultureInfo(language)) ?? value;
        public static string Get(string name, string language) => Resources.GetString(name, CultureInfo.GetCultureInfo(language)) ?? name;
    }
    internal static class Program
    {
        [STAThread]
        private static void Main(string[] args)
        {
            var app = new Application();
            app.DispatcherUnhandledException += (s, e) => { MessageBox.Show(AppStrings.Get("UnexpectedError", "ru"), "TunnelEye"); e.Handled = true; };
            string open = args.Length == 2 && args[0] == "--open" ? args[1] : null;
            app.Run(new MainWindow(open));
        }
    }
}
