using System.Runtime.InteropServices;

namespace ShowWhatProcessLocksFile.Utils;

public static class Admin
{
    [DllImport("shell32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool IsUserAnAdmin();
}
