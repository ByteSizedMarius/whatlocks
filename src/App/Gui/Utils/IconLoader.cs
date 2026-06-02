using System.Drawing;
using System.Windows;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Media.Imaging;

namespace ShowWhatProcessLocksFile.Gui.Utils;

internal static class IconLoader
{
    public static ImageSource? GetIcon(string executableFullName)
    {
        try
        {
            using var ico = Icon.ExtractAssociatedIcon(executableFullName);
            var image = Imaging.CreateBitmapSourceFromHIcon(ico.Handle, Int32Rect.Empty, BitmapSizeOptions.FromEmptyOptions());
            // Freeze so the bitmap can cross threads: it is created off the UI thread but bound on it.
            image.Freeze();
            return image;
        }
        catch (Exception)
        {
            return null;
        }
    }
}
