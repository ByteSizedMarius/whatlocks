using System.Diagnostics;
using System.Web.Script.Serialization;
using ShowWhatProcessLocksFile.LockFinding;
using ShowWhatProcessLocksFile.LockFinding.Utils;
using ShowWhatProcessLocksFile.Utils;

namespace WhatLocks;

internal static class Program
{
    // Processes we refuse to terminate even when they hold the path: killing them takes
    // down the session or bluescreens the box. The handle-enumeration engine doesn't
    // classify criticality, so we match by image name (Restart Manager would tag these
    // "critical"). Matched against Process.ProcessName, which has no ".exe" suffix.
    private static readonly HashSet<string> KillDenylist = new(StringComparer.OrdinalIgnoreCase)
    {
        "System", "Registry", "Idle", "MemCompression", "smss", "csrss", "wininit",
        "winlogon", "services", "lsass", "lsaiso", "fontdrvhost", "dwm",
    };

    private static int Main(string[] rawArgs)
    {
        var kill = false;
        var json = false;
        var paths = new List<string>();

        foreach (var arg in rawArgs)
        {
            switch (arg)
            {
                case "--kill": kill = true; break;
                case "--json": json = true; break;
                case "-h":
                case "--help": PrintUsage(); return 0;
                default:
                    if (arg.StartsWith("-"))
                    {
                        Console.Error.WriteLine($"whatlocks: unknown option '{arg}'");
                        PrintUsage();
                        return 2;
                    }
                    paths.Add(arg);
                    break;
            }
        }

        if (paths.Count == 0)
        {
            PrintUsage();
            return 2;
        }

        var results = paths.Select(path => ScanPath(path, kill)).ToList();

        if (json)
        {
            Console.WriteLine(new JavaScriptSerializer().Serialize(results.Select(r => r.ToJsonModel()).ToList()));
        }
        else
        {
            PrintHuman(results);
        }

        // Detection alone is a success even with holders found. With --kill, the path may
        // still be locked if any holder was refused or wouldn't die, so report that as non-zero.
        var clean = results.All(r => r.Error is null)
                    && (!kill || results.All(r => r.KillOutcomes.All(o => o.Action == KillAction.Killed)));
        return clean ? 0 : 1;
    }

    private static PathResult ScanPath(string rawPath, bool kill)
    {
        var result = new PathResult { Path = rawPath };

        if (!PathExists(rawPath))
        {
            result.Error = "no such file or directory";
            return result;
        }

        CanonicalPath canonical;
        try
        {
            canonical = new CanonicalPath(rawPath);
        }
        catch (Exception ex)
        {
            result.Error = ex.Message;
            return result;
        }

        result.Path = canonical.Path;
        result.IsDirectory = canonical.IsDirectory;

        try
        {
            result.Holders = LockFinder.FindWhatProcessesLockPath(canonical).ToList();
        }
        catch (Exception ex)
        {
            result.Error = $"lock scan failed: {ex.Message}";
            return result;
        }

        if (kill)
        {
            result.KillOutcomes = KillHolders(result.Holders);
        }

        return result;
    }

    private static List<KillOutcome> KillHolders(IEnumerable<ProcessInfo> holders)
    {
        var outcomes = new List<KillOutcome>();
        var selfPid = Process.GetCurrentProcess().Id;

        foreach (var holder in holders)
        {
            var name = holder.ProcessName ?? "(unknown)";

            if (holder.Pid <= 4 || holder.Pid == selfPid)
            {
                outcomes.Add(new KillOutcome(holder.Pid, name, KillAction.Skipped, "system or self process"));
                continue;
            }

            Process process;
            try
            {
                process = Process.GetProcessById(holder.Pid);
            }
            catch (Exception)
            {
                outcomes.Add(new KillOutcome(holder.Pid, name, KillAction.Skipped, "no longer running"));
                continue;
            }

            // Re-read the live name: guards against PID reuse between scan and kill, and is
            // the authoritative name for the denylist check.
            string liveName;
            try
            {
                liveName = process.ProcessName;
            }
            catch (Exception)
            {
                liveName = name;
            }

            if (KillDenylist.Contains(liveName))
            {
                outcomes.Add(new KillOutcome(holder.Pid, name, KillAction.Skipped, "critical/system process, refusing to kill"));
                continue;
            }

            try
            {
                process.Kill();
                outcomes.Add(process.WaitForExit(5000)
                    ? new KillOutcome(holder.Pid, name, KillAction.Killed, null)
                    : new KillOutcome(holder.Pid, name, KillAction.Failed, "timed out waiting for exit"));
            }
            catch (Exception ex)
            {
                outcomes.Add(new KillOutcome(holder.Pid, name, KillAction.Failed, ex.Message));
            }
        }

        return outcomes;
    }

    private static void PrintHuman(List<PathResult> results)
    {
        foreach (var result in results)
        {
            Console.WriteLine($"== {result.Path} ==");

            if (result.Error != null)
            {
                Console.WriteLine($"  error: {result.Error}");
                Console.WriteLine();
                continue;
            }

            if (result.Holders.Count == 0)
            {
                Console.WriteLine("  No locking processes found.");
            }

            foreach (var holder in result.Holders)
            {
                Console.WriteLine($"  PID {holder.Pid,-6} {holder.ProcessName ?? "(unknown)",-24} user={holder.DomainAndUserName ?? "?"}");
                if (holder.ProcessExecutableFullName != null)
                {
                    Console.WriteLine($"            {holder.ProcessExecutableFullName}");
                }
                foreach (var locked in holder.LockedFileFullNames)
                {
                    Console.WriteLine($"            locks: {locked}");
                }
            }

            foreach (var outcome in result.KillOutcomes)
            {
                var reason = outcome.Reason != null ? $" ({outcome.Reason})" : "";
                Console.WriteLine($"  {outcome.Action.ToString().ToUpperInvariant()}: PID {outcome.Pid} {outcome.ProcessName}{reason}");
            }

            Console.WriteLine();
        }

        // Handle enumeration can't see handles held by other users' or elevated processes
        // unless we're elevated too, so an empty/partial result isn't a hard guarantee.
        if (!Admin.IsUserAnAdmin())
        {
            Console.WriteLine("note: not elevated - holders owned by other users or elevated apps may be hidden.");
            Console.WriteLine("      Re-run elevated (e.g. `sudo whatlocks ...`) if a path looks unlocked but isn't.");
        }
    }

    private static bool PathExists(string path)
    {
        try
        {
            return File.Exists(path) || Directory.Exists(path);
        }
        catch (Exception)
        {
            return false;
        }
    }

    private static void PrintUsage()
    {
        Console.Error.WriteLine("usage: whatlocks [--kill] [--json] <path> [<path> ...]");
        Console.Error.WriteLine("  Reports which processes hold a handle on each path.");
        Console.Error.WriteLine("  --kill  terminate the holders (refuses system/critical processes)");
        Console.Error.WriteLine("  --json  emit machine-readable JSON instead of a table");
    }

    private enum KillAction { Killed, Skipped, Failed }

    private sealed class KillOutcome
    {
        public int Pid { get; }
        public string ProcessName { get; }
        public KillAction Action { get; }
        public string? Reason { get; }

        public KillOutcome(int pid, string processName, KillAction action, string? reason)
        {
            Pid = pid;
            ProcessName = processName;
            Action = action;
            Reason = reason;
        }

        public object ToJsonModel() => new
        {
            pid = Pid,
            processName = ProcessName,
            action = Action.ToString().ToLowerInvariant(),
            reason = Reason,
        };
    }

    private sealed class PathResult
    {
        public string Path { get; set; } = "";
        public bool IsDirectory { get; set; }
        public string? Error { get; set; }
        public List<ProcessInfo> Holders { get; set; } = new();
        public List<KillOutcome> KillOutcomes { get; set; } = new();

        public object ToJsonModel() => new
        {
            path = Path,
            isDirectory = IsDirectory,
            error = Error,
            holders = Holders.Select(holder => new
            {
                pid = holder.Pid,
                processName = holder.ProcessName,
                executablePath = holder.ProcessExecutableFullName,
                user = holder.DomainAndUserName,
                lockedPaths = holder.LockedFileFullNames,
            }).ToList(),
            killOutcomes = KillOutcomes.Select(outcome => outcome.ToJsonModel()).ToList(),
        };
    }
}
