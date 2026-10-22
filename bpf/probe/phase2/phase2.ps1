# phase2.sh for a Windows host: the same rows on the WSL podman machine. Run it in PowerShell, from
# anywhere, with the default machine running:
#
#     ...\bpf\probe\phase2\phase2.ps1 [OUTDIR]
#
# It needs %UserProfile%\.wslconfig holding `[wsl2]` and `isolateDistroCgroup=false`
# (doc/plan-bpf-lsm-cgroup.md, "Environment evidence"), or the containers land in no cgroup of
# their own. The fixture is under %UserProfile%\.cache, which the machine serves under /mnt/<drive>
# (SandboxWorkspace.mountPathOf); the containers mount it with the Windows path as the source. The
# clone of this repository is made by git in the container, from the repository's /mnt path; the
# host-side mount is a second mount point of the C: volume (mountvol), which needs an elevated
# PowerShell and is reported as failed otherwise. The rows, what they leave behind and where the
# output goes are phase2.sh's.
param([string]$OutDir = "")

$ErrorActionPreference = "Continue"
$ProbeImage = "ko-agent-bpf-probe:phase2"
$MachineDir = ".local/share/ko-agent-sandbox/bpf-probe2"
$Ctl = "./$MachineDir/controller"
$Mutate = "/out/mutate"
$PinRoot = "/sys/fs/bpf/ko-agent-bpf-phase2"
$WalkCount = 2000
$ProbeDir = $PSScriptRoot
$RepoDir = (Resolve-Path (Join-Path $ProbeDir "..\..\..")).Path
if ($OutDir -eq "") { $OutDir = Join-Path $ProbeDir "out" }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$OutDir = (Resolve-Path $OutDir).Path
$Transcript = Join-Path $OutDir "transcript.log"
Set-Content -Path $Transcript -Value "" -Encoding UTF8

$Fix = Join-Path $env:USERPROFILE (".cache\ko-agent-bpf-phase2." + $PID)
function MachinePath([string]$windowsPath) {
    "/mnt/" + $windowsPath.Substring(0, 1).ToLower() + "/" + $windowsPath.Substring(3).Replace("\", "/")
}
$FixVm = MachinePath $Fix
$RepoVm = MachinePath $RepoDir
$Tree = "$FixVm/tree"
$Repo = "$FixVm/repo"

$script:passed = 0
$script:failed = 0
function Log([string]$text) { Write-Host $text; Add-Content -Path $Transcript -Value $text -Encoding UTF8 }
function Info([string]$text) { Log "INFO $text" }
function Pass([string]$text) { $script:passed++; Log "PASS $text" }
function Fail([string]$text) { $script:failed++; Log "FAIL $text" }
function Check([string]$desc, [bool]$ok) { if ($ok) { Pass $desc } else { Fail $desc } }
# A command in the machine, as the machine's user; its output is logged and returned as one string.
# The command is one line of sh: PowerShell 5.1 passes a newline-free argument unchanged.
function Vm([string]$command) {
    $out = (& podman machine ssh $command 2>&1 | ForEach-Object { "$_" }) -join "`n"
    $script:vmStatus = $LASTEXITCODE
    Add-Content -Path $Transcript -Value $out -Encoding UTF8
    $out
}
function Field([string]$key, [string]$text) {
    foreach ($line in $text -split "`n") {
        if ($line -match "(^|\s)$key=(\S*)") { return $Matches[2] }
    }
    ""
}
function Has([string]$needle, [string]$text) { $text.Contains($needle) }
function Count([string]$needle, [string]$text) { @($text -split "`n" | Where-Object { $_.Contains($needle) }).Count }
function Step([string]$text) { Log ""; Log "== $text" }
# A multi-line sh script for a container, written on the share and run from there, since a
# newline inside an argument does not survive PowerShell 5.1.
function ScriptFile([string]$name, [string]$body) {
    [IO.File]::WriteAllText((Join-Path $Fix $name), $body.Replace("`r`n", "`n"))
    "$FixVm/$name"
}

function Cleanup {
    Step "cleanup"
    Vm "for d in $PinRoot/*; do sudo -n $Ctl unpin `$d; done; sudo -n rmdir $PinRoot 2>/dev/null; true" | Out-Null
    Vm "rmdir /sys/fs/cgroup/user.slice/user-*.slice/user@*.service/app.slice/ko-agent-bpf2-? 2>/dev/null; true" |
        Out-Null
    Vm ("systemctl --user stop ko-agent-bpf2-hold1 ko-agent-bpf2-hold2 ko-agent-bpf2-1.slice ko-agent-bpf2-2.slice" +
        " 2>/dev/null; true") | Out-Null
    & podman rm -f ko-agent-bpf2-nested 2>&1 | Out-Null
    foreach ($when in "before", "after") {
        $mount = Join-Path $Fix "tree\hostmount-$when"
        if (Test-Path $mount) { & mountvol $mount /D 2>&1 | Out-Null }
    }
    Remove-Item -Recurse -Force $Fix -ErrorAction SilentlyContinue
    Log ""
    Log "passed=$($script:passed) failed=$($script:failed) transcript=$Transcript"
}

try {
    # -----------------------------------------------------------------------
    Step "environment"
    # -----------------------------------------------------------------------
    & podman machine inspect --format '{{.State}}' 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { Log "no default podman machine"; exit 2 }
    Vm "sudo -n true" | Out-Null
    if ($script:vmStatus -ne 0) { Log "sudo -n fails in the machine"; exit 2 }
    $uidVm = (Vm "id -u").Trim()
    $kernelVm = (Vm "uname -r").Trim()
    $manager = (Vm "podman info --format '{{.Host.CgroupManager}}'").Trim()
    $runtime = (Vm "podman info --format '{{.Host.OCIRuntime.Name}} {{.Host.OCIRuntime.Version}}'").Trim()
    Info ("machine user uid=$uidVm kernel=$kernelVm podman=$(& podman --version) cgroup manager=$manager " +
        "runtime=$runtime")
    Vm ("sudo -n sh -c 'findmnt -n /sys/kernel/security >/dev/null || " +
        "mount -t securityfs securityfs /sys/kernel/security'; " +
        "sudo -n sh -c 'findmnt -n /sys/fs/bpf >/dev/null || mount -t bpf bpf /sys/fs/bpf'") | Out-Null
    Info "lsm=$(Vm 'sudo -n cat /sys/kernel/security/lsm')"
    Info "sysctl io_uring_disabled=$(Vm 'cat /proc/sys/kernel/io_uring_disabled 2>/dev/null || echo absent')"
    New-Item -ItemType Directory -Force -Path $Fix | Out-Null
    $findmnt = Vm "findmnt -T $FixVm -o TARGET,SOURCE,FSTYPE,OPTIONS"
    Set-Content -Path (Join-Path $OutDir "findmnt.txt") -Value $findmnt -Encoding UTF8
    $fsType = (Vm "findmnt -T $FixVm -n -o FSTYPE").Trim()
    Info "share: $(($findmnt -split "`n")[1])"
    Vm "sudo -n mkdir -p $PinRoot" | Out-Null

    # -----------------------------------------------------------------------
    Step "build and install the probe"
    # -----------------------------------------------------------------------
    & podman build --build-arg "BUILD_KERNEL=$kernelVm" -t $ProbeImage $ProbeDir 2>&1 | ForEach-Object { "$_" } |
        Add-Content -Path $Transcript -Encoding UTF8
    if ($LASTEXITCODE -ne 0) { Log "the probe image failed to build; the build log is in $Transcript"; exit 2 }
    Vm ("set -eu; mkdir -p $MachineDir; podman create --replace --name ko-agent-bpf2-extract $ProbeImage >/dev/null; " +
        "podman cp ko-agent-bpf2-extract:/out/. $MachineDir/; podman rm ko-agent-bpf2-extract >/dev/null; " +
        "test -x $MachineDir/controller") | Out-Null
    Check "probe installed in the machine" ($script:vmStatus -eq 0)
    $build = Vm "cat $MachineDir/clang-version.txt $MachineDir/build-kernel.txt $MachineDir/objects.sha256"
    Set-Content -Path (Join-Path $OutDir "build.txt") -Value $build -Encoding UTF8
    foreach ($obj in "inventory", "classify") {
        Set-Content -Path (Join-Path $OutDir "$obj.bpf.asm") -Value (Vm "cat $MachineDir/$obj.bpf.asm") -Encoding UTF8
    }
    Info ($build -replace "`n", " ")

    # -----------------------------------------------------------------------
    Step "verifier: every inventory program, then the representative program"
    # -----------------------------------------------------------------------
    $load = Vm "sudo -n $Ctl load inventory.bpf.o"
    $loadStatus = $script:vmStatus
    Set-Content -Path (Join-Path $OutDir "verifier-inventory.txt") -Value $load -Encoding UTF8
    $load -split "`n" | Where-Object { $_ -match "^(load|verifier) " } | ForEach-Object { Log "  $_" }
    Check "every inventory program loads, alone and together: $(Count ' ok=1' $load) loads" `
        ((Count " ok=1" $load) -eq 34 -and $loadStatus -eq 0)
    $load = Vm "sudo -n $Ctl load classify.bpf.o"
    $loadStatus = $script:vmStatus
    Set-Content -Path (Join-Path $OutDir "verifier-classify.txt") -Value $load -Encoding UTF8
    $load -split "`n" | Where-Object { $_ -match "^(load|verifier|prog) " } | ForEach-Object { Log "  $_" }
    Check "the representative program's eight hooks load, alone and together" `
        ((Count " ok=1" $load) -eq 9 -and $loadStatus -eq 0)
    $renameLog = Vm "sudo -n $Ctl verifier-log classify.bpf.o inode_rename /tmp/inode_rename.log"
    $renameLog -split "`n" | Where-Object { $_ -match "^verifier " } | ForEach-Object { Log "  $_" }
    $gz = Vm "gzip -c /tmp/inode_rename.log | base64 -w0"
    [IO.File]::WriteAllBytes((Join-Path $OutDir "classify-inode_rename.log.gz"),
        [Convert]::FromBase64String($gz.Trim()))
    Info "the log is in $(Join-Path $OutDir 'classify-inode_rename.log.gz')"

    # -----------------------------------------------------------------------
    Step "fixture, clone and the attach cgroups"
    # -----------------------------------------------------------------------
    $appSlice = "/user.slice/user-$uidVm.slice/user@$uidVm.service/app.slice"
    function AttachCgroup([int]$n) {
        if ($manager -eq "systemd") {
            Vm ("systemctl --user stop ko-agent-bpf2-hold$n 2>/dev/null; systemctl --user reset-failed 2>/dev/null; " +
                "systemd-run --user --unit=ko-agent-bpf2-hold$n --slice=ko-agent-bpf2-$n.slice /usr/bin/sleep 3600") |
                Out-Null
            $script:cg =
                (Vm "find /sys/fs/cgroup/user.slice -type d -name ko-agent-bpf2-$n.slice 2>/dev/null | head -1").Trim()
            $script:parent = "ko-agent-bpf2-$n.slice"
        } else {
            $script:parent = "$appSlice/ko-agent-bpf2-$n"
            $script:cg = "/sys/fs/cgroup$($script:parent)"
            Vm "mkdir -p $($script:cg)" | Out-Null
        }
    }
    AttachCgroup 1
    $cg1 = $script:cg
    $parent1 = $script:parent
    Check "attach cgroup 1 exists under the user's manager: $cg1" ($cg1 -ne "")
    # The exerciser runs without podman's seccomp profile, which answers file_setattr and
    # io_uring_setup with ENOSYS and refuses a mount in a user namespace before the kernel does:
    # the rows ask what the hooks see.
    $exerciserOpts = @("--userns=keep-id", "--security-opt", "seccomp=unconfined", "--volume", "${Fix}:${FixVm}")
    function InSlice([string]$command) {
        $out = (& podman run --rm --cgroup-parent=$parent1 @exerciserOpts $ProbeImage `
            sh -c $command 2>&1 | ForEach-Object { "$_" }) -join "`n"
        Add-Content -Path $Transcript -Value $out -Encoding UTF8
        $out
    }
    # Rows 50 and 51 mount inside a user namespace, which SELinux refuses to container_t (EACCES on the
    # macOS machine): they run with label=disable, as the sandbox's nesting mode does.
    function InSliceUnlabeled([string]$command) {
        $out = (& podman run --rm --cgroup-parent=$parent1 @exerciserOpts --security-opt label=disable $ProbeImage `
            sh -c $command 2>&1 | ForEach-Object { "$_" }) -join "`n"
        Add-Content -Path $Transcript -Value $out -Encoding UTF8
        $out
    }
    function Outside([string]$command) {
        $out = (& podman run --rm @exerciserOpts --volume "${RepoDir}:${RepoVm}:ro" `
            $ProbeImage sh -c $command 2>&1 | ForEach-Object { "$_" }) -join "`n"
        Add-Content -Path $Transcript -Value $out -Encoding UTF8
        $out
    }
    Outside "$Mutate make-tree $Tree" | Out-Null
    Outside "git -c safe.directory='*' clone -q $RepoVm $Repo" | Out-Null
    Check "the fixture and a clone of this repository exist on the share" `
        ((Test-Path (Join-Path $Fix "tree\.git\config")) -and (Test-Path (Join-Path $Fix "repo\.git")))
    $deepest =
        (Outside "git -C $Repo ls-files | awk -F/ 'NF > max { max = NF; deepest = `$0 } END { print deepest }'").Trim()
    $deepestDepth = ($deepest -split "/").Count
    Info "the clone's deepest tracked file: $deepest (depth $deepestDepth below the root)"
    function DeepFile([int]$depth) {
        $path = "deep"
        for ($i = 2; $i -lt $depth; $i++) { $path = "$path/d" }
        $windows = Join-Path (Join-Path $Fix "tree") ($path.Replace("/", "\") + "\f$depth")
        Set-Content -Path $windows -Value "x" -Encoding ascii
        "$Tree/$path/f$depth"
    }
    $deep32 = DeepFile 32
    $deep63 = DeepFile 63
    # The host-side mount made before the attach: the C: volume mounted a second time at a
    # directory inside the tree, the recorded root, where an ordinary directory's write is allowed
    # ("Mounts").
    $volumeId = (Get-Volume -DriveLetter C).UniqueId
    function HostMount([string]$name) {
        $mount = Join-Path $Fix "tree\hostmount-$name"
        New-Item -ItemType Directory -Force -Path $mount | Out-Null
        & mountvol $mount $volumeId 2>&1 | Out-Null
        $LASTEXITCODE -eq 0
    }
    if (HostMount "before") {
        Info "host mount before the attach: $(Vm "findmnt -n -T $Tree/hostmount-before -o TARGET,FSTYPE | tail -1")"
    } else {
        Info "host mount before the attach: mountvol failed (an elevated PowerShell is needed), not measured"
    }

    # -----------------------------------------------------------------------
    Step "the inventory under every hook, eight hooks per batch"
    # -----------------------------------------------------------------------
    # The batches are phase2.sh's: a hook whose own refusal a row claims shares no batch with a hook
    # the same operation reaches first.
    $batches = @(
        "path_mknod path_mkdir path_symlink path_link path_rename path_unlink path_rmdir path_truncate",
        "inode_create inode_mknod inode_mkdir inode_symlink inode_link inode_rename inode_unlink inode_rmdir",
        ("file_open inode_setxattr inode_removexattr inode_set_acl inode_remove_acl path_chmod path_chown " +
            "inode_permission"),
        "inode_setattr file_permission mmap_file file_ioctl file_ioctl_compat inode_file_setattr file_receive",
        "file_truncate file_mprotect"
    )
    # The attribute hooks of the nested-podman rows, attached to cgroup 2.
    $nestedHooks = ("inode_setattr inode_setxattr inode_removexattr inode_set_acl inode_remove_acl " +
        "inode_file_setattr file_ioctl file_ioctl_compat")
    function BatchOf([string]$name) {
        for ($i = 0; $i -lt $batches.Count; $i++) { if (" $($batches[$i]) " -like "* $name *") { return $i + 1 } }
    }
    $allow1 = ""
    $denyRuns = @{}
    $hitsAllow = @{}
    $hits = ""
    $reported = 0
    for ($b = 1; $b -le 5; $b++) {
        $progs = $batches[$b - 1]
        $attach = Vm ("sudo -n $Ctl attach inventory.bpf.o $cg1 $PinRoot/inv$b --keep-going " +
            "--pin-maps $PinRoot/inv-maps $progs")
        Check "batch $b attached: $(($attach -split "`n" | Where-Object { $_ -match '^attached ' }) -join '')" `
            ((Field "failed" $attach) -eq "0")
        New-Item -ItemType Directory -Force -Path (Join-Path $Fix "b$b") | Out-Null
        Outside "$Mutate prepare $FixVm/b$b allow && $Mutate prepare $FixVm/b$b deny" | Out-Null
        $allow = (InSlice "$Mutate inventory $FixVm/b$b allow skip=50,51") + "`n" +
            (InSliceUnlabeled "$Mutate inventory $FixVm/b$b allow only=50,51")
        Set-Content -Path (Join-Path $OutDir "inventory-b$b-allow.txt") -Value $allow -Encoding UTF8
        if ($b -eq 1) { $allow1 = $allow }
        # The hits after the allowed run alone: a hook's counts before its batch's deny run adds to them.
        $hitsAllow[$b] = Vm "sudo -n $Ctl hits $PinRoot/inv-maps"
        Set-Content -Path (Join-Path $OutDir "hits-allow-b$b.txt") -Value $hitsAllow[$b] -Encoding UTF8
        $deny = (InSlice "$Mutate inventory $FixVm/b$b deny skip=50,51") + "`n" +
            (InSliceUnlabeled "$Mutate inventory $FixVm/b$b deny only=50,51")
        Set-Content -Path (Join-Path $OutDir "inventory-b$b-deny.txt") -Value $deny -Encoding UTF8
        $denyRuns[$b] = $deny
        $reported += ([regex]::Matches($allow, '(?m)^op=')).Count + ([regex]::Matches($deny, '(?m)^op=')).Count
        if ($b -eq 5) {
            $hits = Vm "sudo -n $Ctl hits $PinRoot/inv-maps"
            Set-Content -Path (Join-Path $OutDir "hits.txt") -Value $hits -Encoding UTF8
        }
        Vm "sudo -n $Ctl unpin $PinRoot/inv$b" | Out-Null
    }
    # A run that stops early, at an exerciser error, would leave later operations unmeasured.
    Check "every batch's allowed and deny runs report all 55 operations" ($reported -eq 550)
    # One line per operation: its label, the hooks it reached, `*` on a hook that refused the deny
    # name, and the batches whose deny run answered EPERM.
    $label = @{}; $allowed = @{}; $hooks = @{}; $eperm = @{}; $hitArg = @{}
    foreach ($line in $allow1 -split "`n") {
        if ($line -match "^op=(\d\d) label=(\S+) (\S+)") {
            $label[$Matches[1]] = $Matches[2]
            $allowed[$Matches[1]] = $Matches[3]
        }
    }
    foreach ($b in 1..5) {
        foreach ($line in $denyRuns[$b] -split "`n") {
            if ($line -match "^op=(\d\d) label=\S+ result=EPERM") { $eperm[$Matches[1]] += "$b" }
        }
    }
    foreach ($line in $hits -split "`n") {
        if ($line -match "^hit op=(\d\d) hook=(\S+) calls=(\d+) denied=(\d+) arg=(\S+)") {
            $mark = if ([int]$Matches[4] -gt 0) { "*" } else { "" }
            $hooks[$Matches[1]] += " $($Matches[2])($($Matches[3])$mark)"
            $hitArg["$($Matches[1]) $($Matches[2])"] = $Matches[5]
        }
    }
    $table = @()
    for ($op = 1; $op -le 55; $op++) {
        $key = "{0:D2}" -f $op
        $e = if ($eperm[$key]) { $eperm[$key] } else { "-" }
        $table += "row op=$key $($label[$key]) $($allowed[$key]) hooks=[$($hooks[$key])] eperm_in_batches=$e"
    }
    Set-Content -Path (Join-Path $OutDir "inventory-table.txt") -Value ($table -join "`n") -Encoding UTF8
    $table | ForEach-Object { Log "  $_" }
    function Reached([string]$op, [string[]]$names) {
        foreach ($name in $names) { if (-not (Has " $name(" " $($hooks[$op])")) { return $false } }
        $true
    }
    # HOOK's program counted a refusal of OP's deny name.
    function DeniedBy([string]$op, [string]$name) { " $($hooks[$op])" -match " $name\(\d+\*\)" }
    # DeniedBy, and OP's deny run answered EPERM in HOOK's batch.
    function RefusedBy([string]$op, [string]$name) {
        (DeniedBy $op $name) -and (Has "$(BatchOf $name)" "$($eperm[$op])")
    }
    function RefusedAll([string]$name, [string[]]$ops) {
        foreach ($op in $ops) { if (-not (RefusedBy $op $name)) { return $false } }
        $true
    }
    # HOOK's calls for OP in the allowed run of HOOK's batch.
    function AllowCalls([string]$op, [string]$name) {
        if ($hitsAllow[(BatchOf $name)] -match "(?m)^hit op=$op hook=$name calls=(\d+)") { [int]$Matches[1] } else { 0 }
    }
    Check "creat, openat, openat2 and mknod of a regular file reach inode_create, and are refused there" `
        ((Reached "01" @("inode_create", "path_mknod")) -and (Reached "02" @("inode_create")) -and
         (Reached "03" @("inode_create")) -and (Reached "04" @("inode_create")) -and
         (RefusedAll "inode_create" @("01", "02", "03", "04")))
    Check "a socket bind reaches inode_mknod and is refused there" `
        ((Reached "06" @("inode_mknod")) -and (RefusedBy "06" "inode_mknod"))
    # A FIFO on the share: an earlier LSM may refuse it before the hook.
    $fifoAvc = Vm "sudo -n dmesg | grep 'avc: .*fifo_file' | tail -1 | cut -c1-200"
    if ($fifoAvc -eq "") { $fifoAvc = "none" }
    Info "mkfifo: $($allowed['05']) hooks=[$($hooks['05'])]; the last fifo_file AVC: $fifoAvc"
    Check "symlink reaches inode_symlink and is refused there" `
        ((Reached "08" @("inode_symlink")) -and (RefusedBy "08" "inode_symlink"))
    Check "link by name, by AT_EMPTY_PATH and by /proc/self/fd reach inode_link, refused by either name" `
        ((Reached "09" @("inode_link")) -and (Reached "10" @("inode_link")) -and (Reached "11" @("inode_link")) -and
         (Reached "12" @("inode_link")) -and
         (RefusedAll "inode_link" @("09", "10", "11", "12")))
    if ($allowed['49'] -eq "result=ok") {
        Check "a tmpfile's link reaches inode_link" (Reached "13" @("inode_link"))
    } else {
        Info "a tmpfile's link: O_TMPFILE is unsupported on the share ($($allowed['49']))"
    }
    Check "rename, by either name, RENAME_WHITEOUT and RENAME_EXCHANGE reach inode_rename and are refused there" `
        ((Reached "14" @("inode_rename")) -and (Reached "15" @("inode_rename")) -and
         (Reached "16" @("inode_rename")) -and
         (Reached "17" @("inode_rename")) -and (RefusedAll "inode_rename" @("14", "15", "17")))
    # The allowed run's counts: a refused exchange ends at its first call, so the deny run adds unequally.
    $exchangeCalls = AllowCalls "17" "inode_rename"
    $renameCalls = AllowCalls "14" "inode_rename"
    Check "RENAME_EXCHANGE calls inode_rename twice: $exchangeCalls calls against $renameCalls for a rename" `
        ($exchangeCalls -eq 2 * $renameCalls -and $renameCalls -gt 0)
    Check "unlink reaches inode_unlink and is refused there" `
        ((Reached "18" @("inode_unlink")) -and (RefusedBy "18" "inode_unlink"))
    Check "open for writing, O_RDONLY|O_TRUNC and O_WRONLY|O_TRUNC reach file_open and are refused there" `
        ((Reached "21" @("file_open")) -and (Reached "22" @("file_open")) -and (Reached "24" @("file_open")) -and
         (Reached "25" @("file_open")) -and (RefusedAll "file_open" @("21", "22", "24", "25")))
    Check "O_RDONLY|O_TRUNC, chmod, chown, truncate, utimensat and fchmodat reach inode_setattr, refused there" `
        ((Reached "24" @("inode_setattr")) -and (Reached "31" @("inode_setattr")) -and
         (Reached "32" @("inode_setattr")) -and (Reached "33" @("inode_setattr")) -and
         (Reached "34" @("inode_setattr")) -and (Reached "35" @("inode_setattr")) -and
         (RefusedAll "inode_setattr" @("24", "31", "33", "34", "35")))
    Check "setxattr and removexattr reach their hooks; an ACL set reaches inode_set_acl and not inode_setxattr" `
        ((Reached "37" @("inode_setxattr")) -and (Reached "38" @("inode_removexattr")) -and
         (Reached "39" @("inode_set_acl")) -and -not (Has " inode_setxattr(" " $($hooks['39'])"))
    Check "FS_IOC_SETFLAGS and FS_IOC_FSSETXATTR on a read-only descriptor reach file_ioctl and are refused there" `
        ((Reached "41" @("file_ioctl")) -and (Reached "42" @("file_ioctl")) -and
         (RefusedAll "file_ioctl" @("41", "42")))
    $highArg = $hitArg['47 file_ioctl']
    Check "an ioctl command with a bit above 32 set reaches the hook as the 32-bit command: $highArg" `
        ($hitArg["47 file_ioctl"] -ne $null -and $hitArg["47 file_ioctl"] -eq $hitArg["41 file_ioctl"])
    Check "a descriptor passed over a socket reaches file_receive, and a refused one is dropped with MSG_CTRUNC" `
        ((Reached "54" @("file_receive")) -and (DeniedBy "54" "file_receive") -and
         (Count "op=54 " (($denyRuns[(BatchOf "file_receive")] -split "`n" |
            Where-Object { $_ -match "received=no ctrunc=1" }) -join "`n")) -eq 1)
    $support = ($allow1 -split "`n" | Where-Object { $_ -match "^op=(37|39|41|42|43|44|45|46|49|50|51|52|53|55) " } |
        ForEach-Object { $_ -replace "^op=\d+ label=", "" }) -join ";"
    Info "share support: $support"
    Info "io_uring_setup with label=disable: $(InSliceUnlabeled "$Mutate inventory $FixVm/b5 allow only=53")"
    Info "overlayfs kernel messages: $(Vm "sudo -n dmesg | grep -i overlayfs | tail -3 | cut -c1-160 | tr '\n' ';'")"
    Info "the machine's last AVC denials: $(Vm "sudo -n dmesg | grep 'avc: ' | tail -3 | cut -c1-160 | tr '\n' ';'")"
    Vm "sudo -n $Ctl unpin $PinRoot/inv-maps" | Out-Null

    # -----------------------------------------------------------------------
    Step "the representative program: the rules filled to the map, the corpus, git, the walk's cost"
    # -----------------------------------------------------------------------
    $defaults = Get-Content (Join-Path $RepoDir "src\main\resources\agentsandbox\file-rule-defaults") |
        ForEach-Object { ($_ -replace "#.*", "").Trim() } | Where-Object { ($_ -split "\s+").Count -eq 2 }
    $lines = @($defaults)
    for ($i = $lines.Count; $i -lt 128; $i++) { $lines += "read-only zz-filler-$i" }
    [IO.File]::WriteAllText((Join-Path $Fix "rules.txt"), (($lines -join "`n") + "`n"))
    $attach = Vm ("sudo -n $Ctl attach classify.bpf.o $cg1 $PinRoot/classify --fs-type $fsType " +
        "--rules $FixVm/rules.txt " +
        "--root workspace=$Tree --root gitdir=$Tree/.git/modules/sub --root workspace=$Repo " +
        "file_open inode_create inode_mknod inode_symlink inode_link inode_rename inode_unlink inode_setattr")
    $attach -split "`n" | Where-Object { $_ -match "^(root|policy|attached) " } | ForEach-Object { Log "  $_" }
    Check "the representative program attached with 128 rules and three roots" `
        ((Field "count" $attach) -eq "8" -and (Field "rule_count" $attach) -eq "128")
    if ((Field "count" $attach) -eq "8") {
        $pin = "$PinRoot/classify/file_open"
        $corpus = InSlice "$Mutate corpus $Tree"
        $corpus -split "`n" | Where-Object { $_ -match "MISMATCH|UNSUPPORTED" } | ForEach-Object { Log "  $_" }
        Check "the corpus: $(($corpus -split "`n" | Where-Object { $_ -match '^corpus ' }) -join '')" `
            ((Field "mismatches" $corpus) -eq "0")
        Info (Vm "sudo -n $Ctl last-decision $pin")
        $gitScript = ScriptFile "git.sh" @"
cd $Repo && git status --short > /dev/null && git add -A &&
git -c user.name=probe -c user.email=probe@example.invalid commit -q --allow-empty -m probe &&
git checkout -q -b probe && git log -1 --oneline > /dev/null && git gc -q && echo GIT_OK
(git config probe.key value 2>&1 || echo CONFIG_REFUSED)
(git init -q sub2 2>&1 || echo INIT_REFUSED)
"@
        $gitRun = InSlice "sh $gitScript"
        Check "ordinary git in the clone: status, add, commit, branch, log, gc" (Has "GIT_OK" $gitRun)
        Check "git config and git init in the clone are refused" `
            ((Has "CONFIG_REFUSED" $gitRun) -and (Has "INIT_REFUSED" $gitRun))
        function WalkCost([string]$label, [string]$path) {
            $under = InSlice "$Mutate walk-cost $path $WalkCount"
            $bare = Outside "$Mutate walk-cost $path $WalkCount"
            Info ("walk cost, ${label}: policy open_rdwr=$(Field 'open_rdwr_ns' $under) " +
                "open_rdonly=$(Field 'open_rdonly_ns' $under) lstat=$(Field 'lstat_ns' $under) ns; " +
                "bare open_rdwr=$(Field 'open_rdwr_ns' $bare) open_rdonly=$(Field 'open_rdonly_ns' $bare) " +
                "lstat=$(Field 'lstat_ns' $bare) ns; failed=$(Field 'failed' $under)")
        }
        WalkCost "the clone's deepest file, depth $deepestDepth" "$Repo/$deepest"
        WalkCost "depth 32" $deep32
        WalkCost "depth 63" $deep63
        $stats = Vm "sudo -n $Ctl stats $pin"
        $stats -split "`n" | ForEach-Object { Log "  $_" }
        Set-Content -Path (Join-Path $OutDir "stats.txt") -Value $stats -Encoding UTF8
        Check "every walk settled: no walk gave up" ((Count " gave_up=0 " $stats) -eq 8)
        # The host-side mount made after the attach, and a write inside each from under the policy,
        # beside the control: a write in an ordinary directory of the tree.
        if (HostMount "after") {
            Info "host mount after the attach: $(Vm "findmnt -n -T $Tree/hostmount-after -o TARGET,FSTYPE | tail -1")"
        } else {
            Info "host mount after the attach: mountvol failed, not measured"
        }
        New-Item -ItemType Directory -Force -Path (Join-Path $Fix "tree\hostmount-control") | Out-Null
        $control = InSlice "(echo x > $Tree/hostmount-control/kab2-write) 2>&1 && echo WRITE_OK || echo WRITE_FAIL"
        Check "a write in an ordinary directory of the tree, beside the host mounts, is allowed" `
            (Has "WRITE_OK" $control)
        foreach ($when in "before", "after") {
            if (-not (Test-Path (Join-Path $Fix "tree\hostmount-$when"))) { continue }
            $mountStat = Vm "$Ctl statx $Tree/hostmount-$when"
            $treeStat = Vm "$Ctl statx $Tree"
            $write = InSlice "(echo x > $Tree/hostmount-$when/kab2-write) 2>&1 && echo WRITE_OK || echo WRITE_FAIL"
            Info ("host mount $when the attach: mkdev=$(Field 'mkdev' $mountStat) against the tree's " +
                "$(Field 'mkdev' $treeStat), mode=$(Field 'mode' $mountStat); " +
                "a write inside it under the policy: $($write -replace "`n", ' ')")
            Check "a write inside the host mount made $when the attach is refused under the policy" `
                (Has "WRITE_FAIL" $write)
        }
        $jited = Vm "sudo -n $Ctl jited $pin /tmp/file_open.jited"
        Info $jited
        $fetchAdd = Field "fetch_add_insns" $jited
        Check "the xlated program holds the atomic fetch-add and the jited one a barrier instruction" `
            ($fetchAdd -ne "" -and $fetchAdd -ne "0" -and
             ((Field "ldaddal" $jited) -ne "0" -or (Field "dmb_ish" $jited) -ne "0" -or
              (Field "lock_xadd" $jited) -ne "0"))
        Vm "sudo -n $Ctl unpin $PinRoot/classify" | Out-Null
    } else {
        Info "the corpus, git, walk, host-mount and barrier rows need the attach: skipped"
    }

    # -----------------------------------------------------------------------
    Step "a nested podman under the attribute hooks: recorded, then refused"
    # -----------------------------------------------------------------------
    AttachCgroup 2
    $cg2 = $script:cg
    $parent2 = $script:parent
    $nestedScript = ScriptFile "nested.sh" @'
set -u
export HOME=/tmp/home XDG_RUNTIME_DIR=/tmp/xdg
mkdir -p $HOME/.config/containers $XDG_RUNTIME_DIR
printf '[containers]\nnetns = "host"\nutsns = "host"\ncgroups = "disabled"\n[engine]\nevents_logger = "file"\n' \
    > $HOME/.config/containers/containers.conf
printf '{ "default": [ { "type": "insecureAcceptAnything" } ] }\n' > $HOME/.config/containers/policy.json
printf 'unqualified-search-registries = ["docker.io"]\n' > $HOME/.config/containers/registries.conf
printf '[storage]\ndriver = "overlay"\n[storage.options]\nignore_chown_errors = "true"\n' \
    > $HOME/.config/containers/storage.conf
r() {
    if "$@" > /tmp/step.out 2>&1; then echo "nested $1 $2 $3: ok"
    else echo "nested $1 $2 $3: failed: $(tail -2 /tmp/step.out | tr '\n' ' ')"; fi
}
r podman pull -q docker.io/library/alpine:3.22
r podman run --rm docker.io/library/alpine:3.22 true
r podman run -d --name inner docker.io/library/alpine:3.22 sleep 120
r podman exec inner true
r podman rm -f inner
r podman rmi docker.io/library/alpine:3.22
'@
    # /tmp is a tmpfs as the sandbox's is: containers/storage refuses the overlay driver over an
    # overlay graphroot without a mount program, and the sandbox's graphroot is on ~, a volume. In
    # refuse mode the hooks start refusing once the container runs: its creation, which the outer
    # podman does inside the cgroup, is not what they refuse.
    function NestedRun([string]$mode) {
        & podman rm -f ko-agent-bpf2-nested 2>&1 | Out-Null
        $start = (& podman run -d --name ko-agent-bpf2-nested --cgroup-parent=$parent2 --userns=keep-id --tmpfs /tmp `
            --security-opt=unmask=ALL --security-opt=label=disable --cap-add=SYS_CHROOT --volume "${Fix}:${FixVm}" `
            $ProbeImage sh -c "sleep 3; sh $nestedScript" 2>&1 | ForEach-Object { "$_" }) -join "`n"
        if ($LASTEXITCODE -ne 0) { Log "nested-run start failed: $start" }
        if ($mode -eq "refuse") { Vm "sudo -n $Ctl deny-all $npin 1" | Out-Null }
        & podman wait ko-agent-bpf2-nested 2>&1 | Out-Null
        $out = (& podman logs ko-agent-bpf2-nested 2>&1 | ForEach-Object { "$_" }) -join "`n"
        & podman rm -f ko-agent-bpf2-nested 2>&1 | Out-Null
        Add-Content -Path $Transcript -Value $out -Encoding UTF8
        $out
    }
    $attach = Vm "sudo -n $Ctl attach inventory.bpf.o $cg2 $PinRoot/nested --keep-going $nestedHooks"
    $npin = "$PinRoot/nested/inode_setxattr"
    Check "the attribute hooks attached to cgroup 2" ((Field "failed" $attach) -eq "0")
    Vm "sudo -n $Ctl reset $npin" | Out-Null
    $recorded = NestedRun "record"
    $totals = Vm "sudo -n $Ctl totals $npin"
    $totals -split "`n" | Where-Object { $_ -match "hook=($($nestedHooks -replace ' ', '|')) " } |
        ForEach-Object { Log "  $_" }
    Check "the nested podman pulled, ran, executed into and removed a container while the hooks recorded" `
        ((Count ": ok" $recorded) -eq 6)
    $refused = NestedRun "refuse"
    Info "with the attribute hooks refusing: $(($refused -split "`n" | Where-Object { $_ -match '^nested' }) -join ';')"
    $totals = Vm "sudo -n $Ctl totals $npin"
    $totals -split "`n" | Where-Object { $_ -match "hook=($($nestedHooks -replace ' ', '|')) " } |
        ForEach-Object { Log "  $_" }
    Vm "sudo -n $Ctl unpin $PinRoot/nested" | Out-Null
} finally {
    Cleanup
}
if ($script:failed -ne 0) { exit 1 }
