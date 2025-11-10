#requires -version 5.1

<#!
ACE 进程限制器 PowerShell 版本

此脚本功能：
- 监控 SGuard64.exe 与 SGuardSvc64.exe 进程。
- 将目标进程的优先级调整为 Idle。
- 将目标进程的 CPU 亲和性锁定在最后一个逻辑核心（可配置）。
- 提供简单的图形界面显示日志与状态。
- 首次检测到需要调整的进程时延迟 180 秒再执行限制。
- 之后每 180 秒复查进程状态。

运行要求：
- Windows 平台。
- 以管理员权限执行（脚本会自动尝试以管理员身份重新启动）。
- PowerShell 5.1 及更高版本。
!#>

[CmdletBinding()]
param()

# -----------------------------
# 参数配置
# -----------------------------
$TARGET_PROCESSES = @("SGuard64.exe", "SGuardSvc64.exe")
$CHECK_INTERVAL   = 180   # 检查间隔（秒）
$FIRST_DELAY      = 180   # 首次检测延迟（秒）
$TARGET_CPU       = $null # 目标 CPU 核心（null 表示自动使用最后一个逻辑核心）

# -----------------------------
# 权限检查与提升
# -----------------------------
$identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)

if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "正在尝试以管理员权限重新启动脚本..."
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = "powershell.exe"
    $psi.Arguments = "-ExecutionPolicy Bypass -File `"$PSCommandPath`""
    $psi.Verb = "runas"
    $psi.UseShellExecute = $true

    try {
        [System.Diagnostics.Process]::Start($psi) | Out-Null
    }
    catch {
        Write-Warning "无法以管理员权限重新启动，请手动以管理员身份运行。"
    }

    exit
}

# -----------------------------
# 准备 UI
# -----------------------------
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

[System.Windows.Forms.Application]::EnableVisualStyles()

$form = New-Object System.Windows.Forms.Form
$form.Text = "ACE进程限制器"
$form.Width = 700
$form.Height = 500
$form.StartPosition = "CenterScreen"
$form.AutoScaleMode = "Font"
$form.Font = New-Object System.Drawing.Font("SimHei", 10)

$header = New-Object System.Windows.Forms.Label
$header.Text = "ACE进程限制器 - 监控进程: " + ($TARGET_PROCESSES -join ", ")
$header.Font = New-Object System.Drawing.Font("SimHei", 12, [System.Drawing.FontStyle]::Bold)
$header.AutoSize = $false
$header.Dock = "Top"
$header.TextAlign = "MiddleLeft"
$header.Padding = New-Object System.Windows.Forms.Padding(10)
$form.Controls.Add($header)

$logBox = New-Object System.Windows.Forms.RichTextBox
$logBox.Dock = "Fill"
$logBox.ReadOnly = $true
$logBox.Font = New-Object System.Drawing.Font("SimHei", 10)
$logBox.BackColor = [System.Drawing.Color]::FromArgb(245,245,245)
$form.Controls.Add($logBox)

$statusLabel = New-Object System.Windows.Forms.Label
$statusLabel.Dock = "Bottom"
$statusLabel.BorderStyle = "Fixed3D"
$statusLabel.TextAlign = "MiddleLeft"
$statusLabel.Height = 24
$statusLabel.Text = "就绪 - 等待监控开始"
$statusLabel.Padding = New-Object System.Windows.Forms.Padding(5,0,0,0)
$form.Controls.Add($statusLabel)

$buttonPanel = New-Object System.Windows.Forms.Panel
$buttonPanel.Dock = "Bottom"
$buttonPanel.Height = 60
$form.Controls.Add($buttonPanel)

$stopButton = New-Object System.Windows.Forms.Button
$stopButton.Text = "停止监控"
$stopButton.Width = 120
$stopButton.Height = 32
$stopButton.BackColor = [System.Drawing.Color]::FromArgb(255,68,68)
$stopButton.ForeColor = [System.Drawing.Color]::White
$stopButton.FlatStyle = "Flat"
$stopButton.Font = New-Object System.Drawing.Font("SimHei", 10)
$stopButton.Left = ($buttonPanel.Width - $stopButton.Width) / 2
$stopButton.Top = ($buttonPanel.Height - $stopButton.Height) / 2
$stopButton.Anchor = "Top"
$buttonPanel.Controls.Add($stopButton)

$buttonPanel.Add_Resize({
    $stopButton.Left = ($buttonPanel.Width - $stopButton.Width) / 2
})

# -----------------------------
# 工具函数
# -----------------------------
function Invoke-OnUiThread {
    param(
        [Parameter(Mandatory)] [System.Windows.Forms.Control] $Control,
        [Parameter(Mandatory)] [ScriptBlock] $Action,
        $Argument
    )

    if ($Control.IsDisposed) { return }

    if ($Control.InvokeRequired) {
        $Control.Invoke($Action, $Argument) | Out-Null
    }
    else {
        & $Action $Argument
    }
}

function Add-Log {
    param(
        [string] $Message
    )

    $action = {
        param($msg)
        $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        $entry = "[$timestamp] $msg`n"
        $logBox.AppendText($entry)
        $logBox.SelectionStart = $logBox.TextLength
        $logBox.ScrollToCaret()
        $statusLabel.Text = $msg
    }

    Invoke-OnUiThread -Control $logBox -Action $action -Argument $Message
}

function Get-TargetCoreList {
    if ($null -ne $TARGET_CPU) {
        return @($TARGET_CPU)
    }

    $cpuCount = [Environment]::ProcessorCount
    if ($cpuCount -le 0) {
        return @(0)
    }

    return @($cpuCount - 1)
}

function Convert-AffinityToCoreList {
    param(
        [System.IntPtr] $Affinity
    )

    $mask = $Affinity.ToInt64()
    $cores = @()
    $cpuCount = [Environment]::ProcessorCount
    for ($i = 0; $i -lt $cpuCount; $i++) {
        if ($mask -band (1 -shl $i)) {
            $cores += $i
        }
    }
    return $cores
}

function Convert-CoreListToAffinity {
    param(
        [int[]] $Cores
    )

    $mask = 0
    foreach ($core in $Cores) {
        if ($core -ge 0) {
            $mask = $mask -bor (1 -shl $core)
        }
    }

    return [System.IntPtr]::new($mask)
}

function Compare-CoreSets {
    param(
        [int[]] $A,
        [int[]] $B
    )

    if ($A.Count -ne $B.Count) { return $false }
    $sortedA = $A | Sort-Object
    $sortedB = $B | Sort-Object
    for ($i = 0; $i -lt $sortedA.Count; $i++) {
        if ($sortedA[$i] -ne $sortedB[$i]) {
            return $false
        }
    }
    return $true
}

# -----------------------------
# 监控线程
# -----------------------------
$firstDetection = $true
$targetCoreList = Get-TargetCoreList
$targetAffinity = Convert-CoreListToAffinity -Cores $targetCoreList
$targetPriority = [System.Diagnostics.ProcessPriorityClass]::Idle

$worker = New-Object System.ComponentModel.BackgroundWorker
$worker.WorkerSupportsCancellation = $true

$worker.add_DoWork({
    param($sender, $eventArgs)

    Add-Log "开始监控进程: $($TARGET_PROCESSES -join ', ')"
    Add-Log "目标配置: 优先级=$targetPriority，CPU亲和性=$($targetCoreList -join ', ')"
    Add-Log "检查间隔: $CHECK_INTERVAL 秒，首次延迟: $FIRST_DELAY 秒"

    while (-not $sender.CancellationPending) {
        try {
            foreach ($processName in $TARGET_PROCESSES) {
                $nameWithoutExt = [System.IO.Path]::GetFileNameWithoutExtension($processName)
                $processes = [System.Diagnostics.Process]::GetProcessesByName($nameWithoutExt)

                if (-not $processes -or $processes.Count -eq 0) {
                    Add-Log "未检测到进程: $processName"
                    continue
                }

                foreach ($proc in $processes) {
                    if ($sender.CancellationPending) { break }

                    try {
                        $currentPriority = $proc.PriorityClass
                    }
                    catch {
                        Add-Log "无法获取优先级，跳过进程 $processName (PID: $($proc.Id))"
                        $proc.Dispose()
                        continue
                    }

                    try {
                        $currentAffinity = Convert-AffinityToCoreList -Affinity $proc.ProcessorAffinity
                    }
                    catch {
                        Add-Log "无法获取 CPU 亲和性，跳过进程 $processName (PID: $($proc.Id))"
                        $proc.Dispose()
                        continue
                    }

                    $needAdjust = ($currentPriority -ne $targetPriority) -or (-not (Compare-CoreSets -A $currentAffinity -B $targetCoreList))

                    if ($needAdjust) {
                        Add-Log "需要调整: $processName (PID: $($proc.Id))"
                        Add-Log "  当前: 优先级=$currentPriority, CPU亲和性=$($currentAffinity -join ', ')"
                        Add-Log "  目标: 优先级=$targetPriority, CPU亲和性=$($targetCoreList -join ', ')"

                        if ($firstDetection) {
                            Add-Log "首次检测到，$FIRST_DELAY 秒后进行限制..."
                            for ($remaining = $FIRST_DELAY; $remaining -gt 0; $remaining -= 10) {
                                if ($sender.CancellationPending) { break }
                                $updateAction = {
                                    param($text)
                                    $statusLabel.Text = $text
                                }
                                Invoke-OnUiThread -Control $statusLabel -Action $updateAction -Argument "首次检测到，$remaining 秒后进行限制..."
                                Start-Sleep -Seconds ([Math]::Min(10, $remaining))
                            }
                            $firstDetection = $false
                            if ($sender.CancellationPending) {
                                $proc.Dispose()
                                break
                            }
                        }

                        try {
                            if ($proc.PriorityClass -ne $targetPriority) {
                                $proc.PriorityClass = $targetPriority
                                Add-Log "已调整 $processName (PID: $($proc.Id)) 优先级为 $targetPriority"
                            }
                        }
                        catch {
                            Add-Log "权限不足或失败，无法调整优先级: $processName (PID: $($proc.Id))"
                        }

                        try {
                            $currentAffinityPtr = Convert-CoreListToAffinity -Cores (Convert-AffinityToCoreList -Affinity $proc.ProcessorAffinity)
                            if ($currentAffinityPtr.ToInt64() -ne $targetAffinity.ToInt64()) {
                                $proc.ProcessorAffinity = $targetAffinity
                                Add-Log "已调整 $processName (PID: $($proc.Id)) CPU 亲和性为 $($targetCoreList -join ', ')"
                            }
                        }
                        catch {
                            Add-Log "权限不足或失败，无法调整 CPU 亲和性: $processName (PID: $($proc.Id))"
                        }

                        Start-Sleep -Seconds 5
                    }
                    else {
                        Add-Log "无需调整: $processName (PID: $($proc.Id))"
                    }

                    $proc.Dispose()
                }
            }

            if ($sender.CancellationPending) { break }

            Add-Log "本轮检查结束，$CHECK_INTERVAL 秒后再次检查..."

            for ($remaining = $CHECK_INTERVAL; $remaining -gt 0; $remaining -= 10) {
                if ($sender.CancellationPending) { break }
                $updateAction = {
                    param($text)
                    $statusLabel.Text = $text
                }
                Invoke-OnUiThread -Control $statusLabel -Action $updateAction -Argument "等待下次检查: $remaining 秒"
                Start-Sleep -Seconds ([Math]::Min(10, $remaining))
            }
        }
        catch {
            Add-Log "监控线程出错: $($_.Exception.Message)"
            Start-Sleep -Seconds 10
        }
    }

    Add-Log "监控线程已结束。"
})

$worker.RunWorkerAsync()

# -----------------------------
# 停止按钮与退出逻辑
# -----------------------------
$closeTimer = New-Object System.Windows.Forms.Timer
$closeTimer.Interval = 2000
$closeTimer.Add_Tick({
    $closeTimer.Stop()
    if (-not $form.IsDisposed) {
        $form.Close()
    }
})

$stopButton.Add_Click({
    $stopButton.Enabled = $false
    $stopButton.Text = "退出中..."
    if ($worker.IsBusy) {
        $worker.CancelAsync()
    }
    Add-Log "正在停止监控..."
    $updateAction = {
        param($text)
        $statusLabel.Text = $text
    }
    Invoke-OnUiThread -Control $statusLabel -Action $updateAction -Argument "已停止监控，即将退出"
    $closeTimer.Start()
})

$form.Add_FormClosing({
    param($sender, $event)
    if ($worker.IsBusy -and -not $worker.CancellationPending) {
        $worker.CancelAsync()
    }
})

[System.Windows.Forms.Application]::Run($form)

if ($worker.IsBusy) {
    $worker.CancelAsync()
}

$worker.Dispose()
$closeTimer.Dispose()
$form.Dispose()
