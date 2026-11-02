// Copyright 2026 phvntxm
// SPDX-License-Identifier: Apache-2.0
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Media.Animation;
using System.Windows.Threading;

namespace TunnelEye.App
{
    /// <summary>Decorative drawing; never produces progress or delays collection.</summary>
    public sealed class ArgusEyes : FrameworkElement, IDisposable
    {
        private readonly DispatcherTimer timer;
        private readonly Stopwatch clock = new Stopwatch();
        private readonly Func<bool> motionAllowed;
        private bool active, enabled = true, subscribed, disposed;
        private ImageSource finalFrame;
        public int ActiveEye { get; set; }
        public bool IsAnimating => timer.IsEnabled;
        public bool AnimationsEnabled { get => enabled; set { enabled = value; Update(); } }
        public bool IsActive { get => active; set { active = value; Update(); } }
        public ArgusEyes() : this(() => SystemParameters.ClientAreaAnimation) { }
        public ArgusEyes(Func<bool> systemMotionAllowed)
        {
            motionAllowed = systemMotionAllowed ?? throw new ArgumentNullException(nameof(systemMotionAllowed));
            MinHeight = 80;
            timer = new DispatcherTimer(DispatcherPriority.Render, Dispatcher) { Interval = TimeSpan.FromMilliseconds(40) };
            timer.Tick += Tick;
            Loaded += OnLoaded; Unloaded += OnUnloaded; IsVisibleChanged += (s, e) => Update();
        }
        private void Tick(object sender, EventArgs e) => InvalidateVisual();
        private void OnLoaded(object sender, RoutedEventArgs e)
        {
            if (!disposed && !subscribed) { SystemParameters.StaticPropertyChanged += SystemChanged; subscribed = true; }
            Update();
        }
        private void OnUnloaded(object sender, RoutedEventArgs e) { Stop(); Unsubscribe(); }
        private void SystemChanged(object sender, PropertyChangedEventArgs e)
        {
            if (e.PropertyName == nameof(SystemParameters.ClientAreaAnimation)) Dispatcher.BeginInvoke(new Action(Update));
        }
        public void RefreshMotionPreference() => Update();
        public ImageSource Capture()
        {
            if (!IsAnimating || ActualWidth < 1 || ActualHeight < 1) return null;
            var bitmap = new RenderTargetBitmap((int)ActualWidth, (int)ActualHeight, 96, 96, PixelFormats.Pbgra32);
            bitmap.Render(this); bitmap.Freeze(); return bitmap;
        }
        public void Finish()
        {
            finalFrame = Capture(); active = false; Stop();
            if (finalFrame != null && enabled && motionAllowed()) BeginAnimation(OpacityProperty, new DoubleAnimation(1, 0, TimeSpan.FromMilliseconds(350)));
            InvalidateVisual();
        }
        private void Update()
        {
            var allowMotion = enabled && motionAllowed();
            if (!allowMotion) { BeginAnimation(OpacityProperty, null); finalFrame = null; }
            if (!disposed && IsLoaded && IsVisible && active && allowMotion)
            { if (!timer.IsEnabled) { clock.Restart(); timer.Start(); } }
            else Stop();
            InvalidateVisual();
        }
        private void Stop() { timer.Stop(); clock.Stop(); }
        private void Unsubscribe() { if (subscribed) { SystemParameters.StaticPropertyChanged -= SystemChanged; subscribed = false; } }
        protected override void OnRender(DrawingContext dc)
        {
            base.OnRender(dc);
            dc.DrawRectangle(AppTheme.Surface, null, new Rect(RenderSize));
            if (finalFrame != null) { dc.DrawImage(finalFrame, new Rect(RenderSize)); return; }
            if (!timer.IsEnabled)
            {
                var size = Math.Min(80, Math.Min(ActualWidth, ActualHeight));
                dc.DrawImage(AppTheme.Icon(80, true), new Rect((ActualWidth - size) / 2, (ActualHeight - size) / 2, size, size));
                return;
            }
            var positions = new[,] { { .24, .25, 110, 55 }, { .77, .24, 96, 49 }, { .50, .52, 156, 77 }, { .18, .77, 91, 47 }, { .81, .75, 111, 56 } };
            var elapsed = clock.Elapsed.TotalSeconds;
            var scale = Math.Min(1, ActualWidth / 670);
            for (var i = 0; i < 5; i++)
            {
                var cycle = (elapsed + i * 1.19) % 6.8;
                var blink = cycle < .24 ? 1 - Math.Sin(cycle / .24 * Math.PI) * .97 : 1;
                var alpha = Math.Min(1, Math.Max(0, (elapsed - i * .13) / 1.1));
                DrawEye(dc, new Point(positions[i, 0] * ActualWidth, positions[i, 1] * ActualHeight), positions[i, 2] * scale,
                    positions[i, 3] * scale, blink, Math.Sin((elapsed + i * 1.73) * .32), Math.Cos((elapsed + i * 1.73) * .27), i == ActiveEye, alpha);
            }
        }
        private static void DrawEye(DrawingContext dc, Point center, double width, double height, double blink, double gazeX, double gazeY, bool active, double alpha)
        {
            var h = height * Math.Max(.025, blink);
            var geometry = new StreamGeometry();
            using (var g = geometry.Open())
            {
                g.BeginFigure(new Point(-width / 2, 0), true, true);
                g.BezierTo(new Point(-width * .22, -h * .76), new Point(width * .20, -h * .76), new Point(width / 2, 0), true, false);
                g.BezierTo(new Point(width * .20, h * .76), new Point(-width * .22, h * .76), new Point(-width / 2, 0), true, false);
            }
            geometry.Freeze();
            dc.PushTransform(new TranslateTransform(center.X, center.Y));
            dc.PushOpacity(alpha * (active ? 1 : .60));
            if (active)
            {
                dc.PushOpacity(.10); dc.DrawGeometry(null, new Pen(AppTheme.Accent, 7), geometry); dc.Pop();
                dc.PushOpacity(.07); dc.DrawGeometry(null, new Pen(AppTheme.Accent, 13), geometry); dc.Pop();
            }
            var pen = new Pen(AppTheme.Accent, active ? 1.7 : 1.1);
            dc.DrawGeometry(null, pen, geometry); dc.PushClip(geometry);
            var pupil = new Point(gazeX * width * .085, gazeY * height * .095);
            dc.DrawEllipse(null, pen, pupil, height * .21, height * .21);
            dc.DrawEllipse(AppTheme.Accent, null, pupil, height * .055, height * .055);
            dc.Pop(); dc.Pop(); dc.Pop();
        }
        public void Dispose()
        {
            if (disposed) return;
            disposed = true; Stop(); Unsubscribe(); timer.Tick -= Tick;
            BeginAnimation(OpacityProperty, null); finalFrame = null;
            Loaded -= OnLoaded; Unloaded -= OnUnloaded;
        }
    }
}
