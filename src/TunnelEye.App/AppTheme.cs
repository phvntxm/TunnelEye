// Copyright 2026 phvntxm
// SPDX-License-Identifier: Apache-2.0
using System;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Imaging;

namespace TunnelEye.App
{
    public static class AppTheme
    {
        public static readonly SolidColorBrush Background = Brush("#202123");
        public static readonly SolidColorBrush Surface = Brush("#2B2D30");
        public static readonly SolidColorBrush Raised = Brush("#34373B");
        public static readonly SolidColorBrush Text = Brush("#ECECEC");
        public static readonly SolidColorBrush Muted = Brush("#B5B7BA");
        public static readonly SolidColorBrush Line = Brush("#42454A");
        public static readonly SolidColorBrush Accent = Brush("#F28C38");
        public static readonly SolidColorBrush Critical = Brush("#F18B91");
        public static readonly SolidColorBrush Important = Brush("#E6C568");
        public static readonly SolidColorBrush Healthy = Brush("#78C39B");
        private static SolidColorBrush Brush(string value)
        {
            var brush = new SolidColorBrush((Color)ColorConverter.ConvertFromString(value));
            brush.Freeze(); return brush;
        }
        public static void Apply(FrameworkElement element) => element.Resources.MergedDictionaries.Add(
            new ResourceDictionary { Source = new Uri("/TunnelEye;component/Theme.xaml", UriKind.Relative) });
        public static ImageSource Icon(int size, bool transparentBackground = false)
        {
            var drawing = (DrawingImage)Application.LoadComponent(new Uri("/TunnelEye;component/Assets/Argus.xaml", UriKind.Relative));
            if (transparentBackground)
            {
                var group = (DrawingGroup)drawing.Drawing.Clone();
                ((GeometryDrawing)group.Children[0]).Brush = Brushes.Transparent;
                drawing = new DrawingImage(group);
            }
            var visual = new DrawingVisual();
            using (var context = visual.RenderOpen()) context.DrawImage(drawing, new Rect(0, 0, size, size));
            var bitmap = new RenderTargetBitmap(size, size, 96, 96, PixelFormats.Pbgra32);
            bitmap.Render(visual); bitmap.Freeze(); return bitmap;
        }
    }
}
