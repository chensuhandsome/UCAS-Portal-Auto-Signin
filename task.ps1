param(
    [ValidateSet('Install', 'Uninstall', 'Status')]
    [string]$Action = 'Status',
    [string]$TaskName = 'CampusAutoLogin',
    [string]$ScriptPath = (Join-Path $PSScriptRoot 'auto-login.ps1')
)

$ErrorActionPreference = 'Stop'

$runningOnWindows = $env:OS -eq 'Windows_NT' -or $PSVersionTable.Platform -eq 'Win32NT'
if (-not $runningOnWindows) {
    throw 'task.ps1 uses Windows Task Scheduler. On Ubuntu, use systemd/cron to run: pwsh ./run-autologin.ps1'
}

function Get-CampusAutoLoginTask {
    param([string]$Name)
    return Get-ScheduledTask -TaskName $Name -ErrorAction SilentlyContinue
}

switch ($Action) {
    'Install' {
        if (-not (Test-Path -LiteralPath $ScriptPath)) {
            throw "Script not found: $ScriptPath"
        }

        $resolvedScriptPath = (Resolve-Path -LiteralPath $ScriptPath).Path
        $powershell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
        $argument = "-NoProfile -ExecutionPolicy Bypass -File `"$resolvedScriptPath`""

        $taskAction = New-ScheduledTaskAction -Execute $powershell -Argument $argument
        $trigger = New-ScheduledTaskTrigger -AtStartup
        $principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel LeastPrivilege
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)

        Register-ScheduledTask -TaskName $TaskName -Action $taskAction -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
        Write-Host "Installed scheduled task: $TaskName"
        Write-Host "Command: $powershell $argument"
        Write-Host 'It will run at Windows startup after this user logs in.'
    }

    'Uninstall' {
        $task = Get-CampusAutoLoginTask -Name $TaskName
        if ($null -eq $task) {
            Write-Host "Scheduled task not found: $TaskName"
            exit 0
        }

        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Write-Host "Removed scheduled task: $TaskName"
    }

    'Status' {
        $task = Get-CampusAutoLoginTask -Name $TaskName
        if ($null -eq $task) {
            Write-Host "Scheduled task not installed: $TaskName"
            exit 0
        }

        $taskInfo = Get-ScheduledTaskInfo -TaskName $TaskName
        [pscustomobject]@{
            TaskName = $task.TaskName
            State = $task.State
            LastRunTime = $taskInfo.LastRunTime
            LastTaskResult = $taskInfo.LastTaskResult
            NextRunTime = $taskInfo.NextRunTime
        } | Format-List
    }
}
