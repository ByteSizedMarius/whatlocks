using ShowWhatProcessLocksFile.LockFinding.Utils;
using System.Diagnostics;
using System.Reflection;
using System.Windows;

namespace ShowWhatProcessLocksFile.Utils;

internal static class Elevation
{
    public static void RestartAsAdmin(CanonicalPath canonicalPath)
    {
        new Process
        {
            // some of `\` signs can be interpreted as escape sequences.
            StartInfo = new ProcessStartInfo(Assembly.GetExecutingAssembly().Location, $"\"{canonicalPath.Path.Replace("\\", "/")}\"")
            {
                UseShellExecute = true,
                Verb = "runas"
            }
        }.Start();
        Application.Current.Shutdown();
    }
}
