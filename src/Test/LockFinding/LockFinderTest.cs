using NUnit.Framework;
using NUnit.Framework.Legacy;
using Polyfills;
using ShowWhatProcessLocksFile.LockFinding;
using ShowWhatProcessLocksFile.LockFinding.Utils;
using System.Globalization;
using System.IO;

namespace Test.LockFinding;

[TestFixture]
[Parallelizable(scope: ParallelScope.All)]
internal class LockFinderTest
{
    [TestCase(@"C:\PathThatDoesNotExist")]
    [TestCase(@"C:\Windows\system.ini")] // existing but not locked path
    public void Returns_empty_list_If_path_does_not_exist_or_not_locked(string path)
    {
        var processes = LockFinder.FindWhatProcessesLockPath(new CanonicalPath(path));
        ClassicAssert.IsEmpty(processes);
    }

    [TestCase(
        @"C:\Windows\",
        "svchost.exe",
        new[]
        {
            @"C:\Windows\System32\en-US\svchost.exe.mui"
        })]
    [TestCase(
        @"C:\Windows",
        "explorer.exe",
        new[]
        {
            @"C:\Windows\en-US\explorer.exe.mui",
            @"C:\Windows\en-US\explorer.exe.mUi",
            @"C:\Windows\Fonts\StaticCache.dat",
            @"C:\Windows\System32\",
            @"C:\WINDOWS\SYSTEM32\ntdll.dll"
        })]
    [TestCase(
        @"C:\Windows\System32",
        "explorer.exe",
        new[]
        {
            @"C:\Windows\System32\",
            @"C:\WINDOWS\SYSTEM32\ntdll.dll"
        })]
    [TestCase(
        @"C:\windows",
        "exploRer.exe",
        new[]
        {
            @"C:\Windows\en-US\explorer.exe.mui",
            @"C:\Windows\en-US\explorer.exe.mUi",
            @"C:\Windows\Fonts\StaticCache.dat"
        })]
    [TestCase(
        @"C:/windows",
        "exploRer.exe",
        new[]
        {
            @"C:\Windows\en-US\explorer.exe.mui",
            @"C:\Windows\en-US\explorer.exe.mUi",
            @"C:\Windows\Fonts\StaticCache.dat"
        })]
    [TestCase(
        @"C:\WINDOWS\SYSTEM32\ntdll.dll",
        "explorer.exe",
        new[]
        {
            @"C:\WINDOWS\SYSTEM32\ntdll.dll"
        })]
    [TestCase(
        @"C:\Windows\en-US\explorer.exe.mui",
        "explorer.exe",
        new[]
        {
            @"C:\Windows\en-US\explorer.exe.mui"
        })]
    [TestCase(
        @"C:\",
        "exploRer.exe",
        new[]
        {
            @"C:\Windows\en-US\explorer.exe.mui",
            @"C:\Windows\en-US\explorer.exe.mUi",
            @"C:\Windows\Fonts\StaticCache.dat"
        })]
    [TestCase(
        @"C:/",
        "exploRer.exe",
        new[]
        {
            @"C:\Windows\en-US\explorer.exe.mui",
            @"C:\Windows\en-US\explorer.exe.mUi",
            @"C:\Windows\Fonts\StaticCache.dat"
        })]
    public void If_path_is_locked_Returns_information_about_processes_that_lock_this_path(string path, string processName, IEnumerable<string> pathThatShouldBeLocked)
    {
        var processes = LockFinder.FindWhatProcessesLockPath(new CanonicalPath(ToCurrentUiLanguage(path))).ToList();

        var info = AssertContainsProcessInfo(
            processes,
            p => string.Equals(p.ProcessName, processName, StringComparison.InvariantCultureIgnoreCase),
            $"{processName} process should lock files in the '{path}'");
        foreach (var p in pathThatShouldBeLocked)
        {
            AssertLocksPath(info, ToCurrentUiLanguage(p));
        }

        Assert.That(info.ProcessExecutableFullName, Is.Not.Null);
    }

    [Test]
    public void Returns_only_information_related_to_the_requested_path()
    {
        var processes = LockFinder.FindWhatProcessesLockPath(new CanonicalPath(@"C:\Program Files")).ToList();
        foreach (var lockedPath in processes.SelectMany(proc => proc.LockedFileFullNames))
        {
            StringAssert.DoesNotStartWith(@"C:\Program Files (x86)", lockedPath);
        }
    }

    [Test]
    [Explicit]
    public void TestPerformance()
    {
        var stopwatch = System.Diagnostics.Stopwatch.StartNew();
        for (int i = 0; i < 5; i++)
        {
            var processes = LockFinder.FindWhatProcessesLockPath(new CanonicalPath(@"C:\Program Files")).ToList();
            Console.WriteLine($"Iteration {i}. FindWhatProcessesLockPath took {stopwatch.Elapsed}. Process count {processes.Count}");
        }
        stopwatch.Stop();
        Console.WriteLine($"Whole test took {stopwatch.Elapsed}");
    }

    // This test requires a network share drive. I used WSL.
    [Test]
    [Explicit]
    public void Shows_files_locked_on_network_share_drive()
    {
        var uniqueTmpFileOnSharedDrive = $@"\\wsl.localhost\Ubuntu-24.04\var\tmp\uniqueTmpFile_{Guid.NewGuid():N}.txt";

        try
        {
            using (File.Create(uniqueTmpFileOnSharedDrive))
            {
                var infos = LockFinder.FindWhatProcessesLockPath(new CanonicalPath(uniqueTmpFileOnSharedDrive)).ToList();
                Assert.Greater(infos.Count, 0);
                AssertLocksPath(infos[0], uniqueTmpFileOnSharedDrive);

                infos = LockFinder.FindWhatProcessesLockPath(new CanonicalPath(@"\\wsl.localhost\Ubuntu-24.04\var\tmp")).ToList();
                Assert.Greater(infos.Count, 0);
                AssertLocksPath(infos[0], uniqueTmpFileOnSharedDrive);
            }
        }
        finally
        {
            if (File.Exists(uniqueTmpFileOnSharedDrive))
            {
                File.Delete(uniqueTmpFileOnSharedDrive);
            }
        }
    }

    // This test requires a mounted drive. I used Cryptomator with mounting type "WinFsp (Local Drive)"
    [Test]
    [Explicit]
    public void Shows_files_locked_on_mounted_drives()
    {
        var file = @"E:\test\test_doc.docx";

        var infos = LockFinder.FindWhatProcessesLockPath(new CanonicalPath(file)).ToList();
        Assert.Greater(infos.Count, 0);
        AssertLocksPath(infos[0], file);
    }

    // *.mui resources load from the display-language dir (e.g. en-GB), not necessarily the en-US
    // pinned in the TestCases. Map en-US to the running UI language so assertions hold on any
    // English display language.
    private static string ToCurrentUiLanguage(string path) =>
        path.Replace(@"\en-US\", $@"\{CultureInfo.CurrentUICulture.Name}\");

    private static ProcessInfo AssertContainsProcessInfo(IEnumerable<ProcessInfo> processes, Predicate<ProcessInfo> condition, string? errorMessage = null)
    {
        foreach (var proc in processes)
        {
            if (condition(proc))
            {
                return proc;
            }
        }

        throw new AssertionException(errorMessage!);
    }

    private static void AssertLocksPath(ProcessInfo process, string lockedPath)
    {
        var path = process.LockedFileFullNames.FirstOrDefault(p => string.Equals(p, lockedPath, StringComparison.InvariantCultureIgnoreCase));
        ClassicAssert.IsNotNull(path,
            $"{process}\ndoesn't lock the path '{lockedPath}'.\nIt only locks the following paths:\n* {string.Join("\n* ", process.LockedFileFullNames)}");
    }
}
