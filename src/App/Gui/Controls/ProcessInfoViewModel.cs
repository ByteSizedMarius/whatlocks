using System.Windows.Media;
using ShowWhatProcessLocksFile.Gui.Utils;
using ShowWhatProcessLocksFile.LockFinding;

namespace ShowWhatProcessLocksFile.Gui.Controls;

internal class ProcessInfoViewModel(ProcessInfo process) : ViewModelBase
{
    public ProcessInfo Process { get; } = process;

    public ImageSource? Icon { get; } = process.ProcessExecutableFullName is { } exe ? IconLoader.GetIcon(exe) : null;

    private bool isExpanded;

    public bool IsExpanded
    {
        get => isExpanded;
        set
        {
            isExpanded = value;
            OnPropertyChanged();
        }
    }
}
