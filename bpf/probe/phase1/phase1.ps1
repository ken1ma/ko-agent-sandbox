# phase1.sh for a Windows host: the same rows on the WSL podman machine. Run it in PowerShell, from
# anywhere, with the default machine running:
#
#     ...\bpf\probe\phase1\phase1.ps1 [OUTDIR]
#
# It needs %UserProfile%\.wslconfig holding `[wsl2]` and `isolateDistroCgroup=false`
# (doc/plan-bpf-lsm-cgroup.md, "Environment evidence"), or the containers land in no cgroup of
# their own. The fixture is under %UserProfile%\.cache, which the machine serves under /mnt/<drive>
# (SandboxWorkspace.mountPathOf); the containers mount it as unfiltered.ps1 does, the Windows path
# as the source; the host-side renames, hard link and replacement are PowerShell's.
# The rows, what they leave behind and where the output goes are phase1.sh's.
param([string]$OutDir = "")

$ErrorActionPreference = "Continue"
$Marker = "ko-agent-bpf-marker"
$Image = "docker.io/library/alpine:3.22"
$ProbeImage = "ko-agent-bpf-probe:phase1"
$MachineDir = ".local/share/ko-agent-sandbox/bpf-probe"
$Ctl = "./$MachineDir/controller"
$PinRoot = "/sys/fs/bpf/ko-agent-bpf-phase1"
$ProbeDir = $PSScriptRoot
if ($OutDir -eq "") { $OutDir = Join-Path $ProbeDir "out" }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$OutDir = (Resolve-Path $OutDir).Path
$Transcript = Join-Path $OutDir "transcript.log"
Set-Content -Path $Transcript -Value "" -Encoding UTF8

$Fix = Join-Path $env:USERPROFILE (".cache\ko-agent-bpf-phase1." + $PID)
function MachinePath([string]$windowsPath) {
    "/mnt/" + $windowsPath.Substring(0, 1).ToLower() + "/" + $windowsPath.Substring(3).Replace("\", "/")
}
$FixVm = MachinePath $Fix
$MarkerPath = "$FixVm/dir/sub/$Marker"

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
function Step([string]$text) { Log ""; Log "== $text" }

function Cleanup {
    Step "cleanup"
    Vm ("sudo -n $Ctl unpin $PinRoot/1; sudo -n $Ctl unpin $PinRoot/2; sudo -n $Ctl unpin $PinRoot/3; " +
        "sudo -n $Ctl unpin $PinRoot/4; sudo -n rmdir $PinRoot 2>/dev/null; true") | Out-Null
    Vm ("systemctl --user stop ko-agent-bpf-hold1 ko-agent-bpf-hold2 ko-agent-bpf1.slice ko-agent-bpf2.slice " +
        "2>/dev/null; true") | Out-Null
    Vm "rmdir /sys/fs/cgroup/user.slice/user-*.slice/user@*.service/app.slice/ko-agent-bpf? 2>/dev/null; true" |
        Out-Null
    & podman rm -f ko-agent-bpf-scope ko-agent-bpf-closed ko-agent-bpf-below 2>&1 | Out-Null
    if (Test-Path $Fix) { Remove-Item -Recurse -Force $Fix }
    Log ""
    Log "passed=$script:passed failed=$script:failed transcript=$Transcript"
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
    $homeVm = (Vm "echo `$HOME").Trim()
    $manager = (Vm "podman info --format '{{.Host.CgroupManager}}'").Trim()
    $runtime = ((Vm "podman info --format '{{.Host.OCIRuntime.Name}} {{.Host.OCIRuntime.Version}}'") -split "`n")[0]
    Info ("machine user uid=$uidVm kernel=$kernelVm podman=" + (& podman --version) + " cgroup manager=$manager" +
        " runtime=$runtime")
    # wsl.exe prints UTF-16; read it as such for one call.
    $encoding = [Console]::OutputEncoding
    [Console]::OutputEncoding = [Text.Encoding]::Unicode
    $wsl = (& wsl --version 2>&1 | ForEach-Object { "$_" }) -join " "
    [Console]::OutputEncoding = $encoding
    Info "wsl=$wsl"
    # The WSL machine mounts neither securityfs nor a bpffs (measured 2026-10-21); the probe mounts
    # them, which the launcher's controller would have to do as well.
    Info ("mounts: " + (Vm "findmnt -n -o FSTYPE /sys/kernel/security /sys/fs/bpf").Replace("`n", " "))
    Vm ("sudo -n sh -c 'findmnt -n /sys/kernel/security >/dev/null || " +
        "mount -t securityfs securityfs /sys/kernel/security'; " +
        "sudo -n sh -c 'findmnt -n /sys/fs/bpf >/dev/null || mount -t bpf bpf /sys/fs/bpf'") | Out-Null
    Info ("lsm=" + (Vm "sudo -n cat /sys/kernel/security/lsm").Trim())
    Info ("kptr_restrict=" + (Vm "cat /proc/sys/kernel/kptr_restrict").Trim() +
        " bpffs=" + (Vm "stat -f -c %T /sys/fs/bpf").Trim() + ":" + (Vm "stat -c %a:%U /sys/fs/bpf").Trim())
    Info ("rename_lock=" + (Vm "sudo -n grep -w rename_lock /proc/kallsyms | head -3").Replace("`n", " "))
    $findmnt = Vm ("findmnt -T " + (MachinePath $env:USERPROFILE) + " -o TARGET,SOURCE,FSTYPE,OPTIONS")
    Set-Content -Path (Join-Path $OutDir "findmnt.txt") -Value $findmnt -Encoding UTF8
    Info ("share: " + (($findmnt -split "`n")[1]))
    Vm "sudo -n mkdir -p $PinRoot" | Out-Null

    # -----------------------------------------------------------------------
    Step "build and install the probe"
    # -----------------------------------------------------------------------
    $build = (& podman build --build-arg "BUILD_KERNEL=$kernelVm" -t $ProbeImage $ProbeDir 2>&1 |
        ForEach-Object { "$_" }) -join "`n"
    $buildStatus = $LASTEXITCODE
    Add-Content -Path $Transcript -Value $build -Encoding UTF8
    Write-Host (($build -split "`n") | Select-Object -Last 3)
    if ($buildStatus -ne 0) { Log "the probe image failed to build; the build log is in $Transcript"; exit 2 }
    Vm ("set -eu; mkdir -p $MachineDir; podman create --replace --name ko-agent-bpf-extract $ProbeImage >/dev/null; " +
        "podman cp ko-agent-bpf-extract:/out/. $MachineDir/; podman rm ko-agent-bpf-extract >/dev/null; " +
        "test -x $MachineDir/controller") | Out-Null
    Check "probe installed in the machine" ($script:vmStatus -eq 0)
    $buildInfo = Vm "cat $MachineDir/clang-version.txt $MachineDir/build-kernel.txt $MachineDir/lsm_probe.bpf.o.sha256"
    Set-Content -Path (Join-Path $OutDir "build.txt") -Value $buildInfo -Encoding UTF8
    $asm = Vm "cat $MachineDir/lsm_probe.bpf.asm"
    Set-Content -Path (Join-Path $OutDir "lsm_probe.bpf.asm") -Value $asm -Encoding UTF8
    Info ($buildInfo.Replace("`n", " "))
    & podman pull -q $Image 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { Log "cannot pull $Image"; exit 2 }

    # -----------------------------------------------------------------------
    Step "verifier: each program alone, then all eleven"
    # -----------------------------------------------------------------------
    $load = Vm "sudo -n $Ctl load"
    $loadStatus = $script:vmStatus
    Set-Content -Path (Join-Path $OutDir "verifier.txt") -Value $load -Encoding UTF8
    foreach ($line in $load -split "`n") { if ($line -match '^(load|verifier|prog) ') { Log "  $line" } }
    Check "every program loads, alone and together, and the controller exits 0" `
        ((($load -split "`n") | Where-Object { $_ -match ' ok=1' }).Count -eq 12 -and $loadStatus -eq 0)
    Info ("slots before: " + (Field "hooks_in_use" (Vm "sudo -n $Ctl query /sys/fs/cgroup")) + " hooks in use")

    # -----------------------------------------------------------------------
    Step "fixture and the attach cgroup"
    # -----------------------------------------------------------------------
    New-Item -ItemType Directory -Force -Path "$Fix\dir\sub", "$Fix\dir\$Marker-dir" | Out-Null
    Set-Content -Path "$Fix\dir\sub\$Marker" -Value "marker" -Encoding ASCII
    Set-Content -Path "$Fix\dir\sub\other" -Value "other" -Encoding ASCII
    $MarkerDir = "$FixVm/dir/$Marker-dir"
    # The attach cgroup, by the machine's cgroup manager: under systemd a transient slice held by a
    # unit, under cgroupfs (the WSL machine, measured 2026-10-21) a directory under the user's
    # delegated subtree, which podman takes as an absolute --cgroup-parent and keeps until removed.
    $appSlice = "/user.slice/user-$uidVm.slice/user@$uidVm.service/app.slice"
    function AttachCgroup([int]$n) { # returns the cgroup's sysfs path and the --cgroup-parent value
        if ($manager -eq "systemd") {
            Vm ("systemctl --user stop ko-agent-bpf-hold$n 2>/dev/null; systemctl --user reset-failed 2>/dev/null; " +
                "systemd-run --user --unit=ko-agent-bpf-hold$n --slice=ko-agent-bpf$n.slice /usr/bin/sleep 1800") |
                Out-Null
            $cg = (Vm "find /sys/fs/cgroup/user.slice -type d -name ko-agent-bpf$n.slice 2>/dev/null | head -1").Trim()
            return @($cg, "ko-agent-bpf$n.slice")
        }
        $parent = "$appSlice/ko-agent-bpf$n"
        Vm "mkdir -p /sys/fs/cgroup$parent" | Out-Null
        return @("/sys/fs/cgroup$parent", $parent)
    }
    function ReleaseHold([int]$n) { # what kept the cgroup alive lets go; nothing under cgroupfs
        if ($manager -eq "systemd") { Vm "systemctl --user stop ko-agent-bpf-hold$n" | Out-Null }
    }
    function RemoveCgroup([int]$n) {
        if ($manager -eq "systemd") { Vm "systemctl --user stop ko-agent-bpf$n.slice" | Out-Null }
        else { Vm "rmdir /sys/fs/cgroup$appSlice/ko-agent-bpf$n" | Out-Null }
    }
    $cg1, $parent1 = AttachCgroup 1
    Check "attach cgroup 1 exists under the user's manager: $cg1" ($cg1 -ne "")
    $attach = Vm "sudo -n $Ctl attach $cg1 $PinRoot/1 file_open"
    Check ("file_open attached and pinned: " + (($attach -split "`n") | Where-Object { $_ -match '^attach ' })) `
        ((Field "ok" $attach) -eq "1")
    $query = Vm "sudo -n $Ctl query $cg1"
    Check "query lists one program, on bpf_lsm_file_open" `
        ((Field "prog_cnt" $query) -eq "1" -and (Has "hook=bpf_lsm_file_open" $query))

    function InSlice([string]$shellScript) {
        $out = (& podman run --rm "--cgroup-parent=$parent1" --userns=keep-id --volume "${Fix}:${FixVm}" `
            $Image sh -c $shellScript 2>&1 | ForEach-Object { "$_" }) -join "`n"
        Add-Content -Path $Transcript -Value $out -Encoding UTF8
        $out
    }
    function Outside([string]$shellScript) {
        $out = (& podman run --rm --userns=keep-id --volume "${Fix}:${FixVm}" $Image sh -c $shellScript 2>&1 |
            ForEach-Object { "$_" }) -join "`n"
        Add-Content -Path $Transcript -Value $out -Encoding UTF8
        $out
    }
    $run1 = InSlice ("cat $MarkerPath > /dev/null && echo READ_OK; " +
        "(echo x >> $MarkerPath) 2>&1 && echo WRITE_OK || echo WRITE_FAIL; " +
        "(echo x >> $FixVm/dir/sub/other) 2>&1 && echo OTHER_OK || echo OTHER_FAIL")
    Check "under cgroup 1, the marker opens for reading" (Has "READ_OK" $run1)
    Check "under cgroup 1, the marker is refused for writing with EPERM" `
        ((Has "WRITE_FAIL" $run1) -and (Has "not permitted" $run1))
    Check "under cgroup 1, the sibling file is written" (Has "OTHER_OK" $run1)
    $run2 = Outside "(echo x >> $MarkerPath) 2>&1 && echo WRITE_OK || echo WRITE_FAIL"
    Check "outside cgroup 1, the marker is written" (Has "WRITE_OK" $run2)

    # -----------------------------------------------------------------------
    Step "identity through the share"
    # -----------------------------------------------------------------------
    function Sx([string]$path) { Vm "$Ctl statx $path" }
    function Ident([string]$statxLine) { (Field "mkdev" $statxLine) + ":" + (Field "ino" $statxLine) }
    function SameIdentity([string]$desc, [string]$a, [string]$b) {
        Check "${desc}: $(Ident $a) vs $(Ident $b)" `
            ((Field "mkdev" $a) -eq (Field "mkdev" $b) -and (Field "ino" $a) -eq (Field "ino" $b) -and
                (Field "ino" $a) -ne "")
    }
    function DifferentIdentity([string]$desc, [string]$a, [string]$b) {
        Check "${desc}: $(Ident $a) vs $(Ident $b)" `
            ((Field "ino" $a) -ne "" -and (Field "ino" $b) -ne "" -and (Field "ino" $a) -ne (Field "ino" $b))
    }
    function ProgramMatches([string]$desc, [string]$lastOpen, [string]$statxLine) {
        Check "${desc}: $(Field 's_dev' $lastOpen):$(Field 'i_ino' $lastOpen) fs_type=$(Field 'fs_type' $lastOpen)" `
            ((Field "i_ino" $lastOpen) -ne "" -and (Field "s_dev" $lastOpen) -eq (Field "mkdev" $statxLine) -and
                (Field "i_ino" $lastOpen) -eq (Field "ino" $statxLine))
    }
    $f0 = Sx $MarkerPath
    $d0 = Sx "$FixVm/dir/sub"
    Info $f0
    Info $d0
    $p0 = Vm "sudo -n $Ctl last-open $PinRoot/1/file_open"
    Info $p0
    ProgramMatches "the program's (s_dev, i_ino) equals statx's (mkdev, ino)" $p0 $f0
    InSlice "ls $MarkerDir > /dev/null" | Out-Null
    ProgramMatches "the program reads a directory's identity as statx does" `
        (Vm "sudo -n $Ctl last-open $PinRoot/1/file_open") (Sx $MarkerDir)
    Rename-Item -Path "$Fix\dir\sub" -NewName "sub2"
    SameIdentity "directory identity after a host rename of the directory" $d0 (Sx "$FixVm/dir/sub2")
    Rename-Item -Path "$Fix\dir\sub2" -NewName "sub"
    Rename-Item -Path "$Fix\dir\sub\$Marker" -NewName "renamed"
    SameIdentity "file identity after a host rename of the file" $f0 (Sx "$FixVm/dir/sub/renamed")
    Rename-Item -Path "$Fix\dir\sub\renamed" -NewName $Marker
    Rename-Item -Path "$Fix\dir" -NewName "dir2"
    SameIdentity "file identity after a host rename of an ancestor" $f0 (Sx "$FixVm/dir2/sub/$Marker")
    SameIdentity "directory identity after a host rename of its parent" $d0 (Sx "$FixVm/dir2/sub")
    Rename-Item -Path "$Fix\dir2" -NewName "dir"
    Vm "sync; sudo -n sh -c 'echo 2 > /proc/sys/vm/drop_caches'" | Out-Null
    SameIdentity "file identity after the guest dropped its caches" $f0 (Sx $MarkerPath)
    SameIdentity "directory identity after the guest dropped its caches" $d0 (Sx "$FixVm/dir/sub")
    New-Item -ItemType HardLink -Path "$Fix\dir\sub\link" -Value "$Fix\dir\sub\$Marker" | Out-Null
    SameIdentity "the two names of a host-made hard link" (Sx $MarkerPath) (Sx "$FixVm/dir/sub/link")
    Remove-Item "$Fix\dir\sub\link"
    # On virtiofs the guest answers ENOENT for a replaced name for a few seconds (measured 2026-10-21).
    function WaitVisible([string]$path) { # the path's statx line once it appears, within 30 s
        $waited = 0
        do {
            $line = Sx $path
            if (Has " ino=" $line) { break }
            Start-Sleep -Milliseconds 500
            $waited += 500
        } while ($waited -lt 30000)
        Info "$path became visible to the guest after about $waited ms"
        $line
    }
    Remove-Item "$Fix\dir\sub\$Marker"
    Set-Content -Path "$Fix\dir\sub\$Marker" -Value "replaced" -Encoding ASCII
    $f5 = WaitVisible $MarkerPath
    DifferentIdentity "a host-made replacement at the same name differs" $f0 $f5
    InSlice "cat $MarkerPath > /dev/null" | Out-Null
    $p5 = Vm "sudo -n $Ctl last-open $PinRoot/1/file_open"
    ProgramMatches "the program reads the replacement's identity" $p5 $f5
    Remove-Item -Recurse -Force "$Fix\dir\sub"
    New-Item -ItemType Directory -Path "$Fix\dir\sub" | Out-Null
    Set-Content -Path "$Fix\dir\sub\$Marker" -Value "marker" -Encoding ASCII
    DifferentIdentity "a host-made replacement of the directory differs" $d0 (WaitVisible "$FixVm/dir/sub")

    # -----------------------------------------------------------------------
    Step "a second cgroup shares the slot; ten hooks fit, an eleventh does not"
    # -----------------------------------------------------------------------
    $cg2, $parent2 = AttachCgroup 2
    $attach2 = Vm "sudo -n $Ctl attach $cg2 $PinRoot/2 file_open"
    Check "file_open attached to cgroup 2 as well" ((Field "ok" $attach2) -eq "1")
    $query2 = Vm "sudo -n $Ctl query $cg2"
    Check ("one hook in use for two cgroups: hooks_in_use=" + (Field "hooks_in_use" $query2) +
            " links=" + (Field "links" $query2)) `
        ((Field "hooks_in_use" $query2) -eq "1" -and (Field "links" $query2) -eq "2")
    $more = Vm ("sudo -n $Ctl attach $cg2 $PinRoot/2 --keep-going inode_create inode_mknod inode_symlink inode_link " +
        "inode_rename inode_unlink inode_setattr file_receive inode_mkdir inode_rmdir")
    foreach ($line in $more -split "`n") { if ($line -match '^attach ') { Log "  $line" } }
    # The eleventh hook's attach answers EINVAL: __cgroup_bpf_attach folds bpf_cgroup_atype_find's
    # -E2BIG into it (kernel/bpf/cgroup.c).
    $attached = ($more -split "`n") | Where-Object { $_ -match '^attached ' }
    Check "nine more hooks attach, the tenth distinct one fails with EINVAL: $attached" `
        ((Field "count" $more) -eq "9" -and (Has "name=inode_rmdir ok=0 errno=22" $more))
    Info ((((Vm "sudo -n $Ctl query $cg2") -split "`n") | Where-Object { $_ -match '^slots ' }))
    Vm "sudo -n $Ctl unpin $PinRoot/2" | Out-Null
    $slots = ((Vm "sudo -n $Ctl query $cg1") -split "`n") | Where-Object { $_ -match '^slots ' }
    Info "after unpinning cgroup 2: $slots"

    # -----------------------------------------------------------------------
    Step "the attach cgroup with a container below, then empty: populated, the manager, and the link"
    # -----------------------------------------------------------------------
    $attach2 = Vm "sudo -n $Ctl attach $cg2 $PinRoot/2 file_open"
    $before = Vm "sudo -n $Ctl link-info $PinRoot/2/file_open"
    Info $before
    # A container below the attach cgroup, which holds no task of its own: cgroup.events's populated
    # counts the descendants' tasks (Documentation/admin-guide/cgroup-v2.rst) and cgroup.procs does
    # not, which is what the reconcile of "Lifecycle", 7, rests on.
    function Populated([string]$cgroup) { (Vm "sed -n 's/^populated //p' $cgroup/cgroup.events").Trim() }
    & podman run -d --rm --name ko-agent-bpf-below "--cgroup-parent=$parent2" $Image sleep 600 | Out-Null
    $procs2 = (Vm "wc -l < $cg2/cgroup.procs").Trim()
    Check ("with a container below it, cgroup 2 holds no task of its own and reads populated 1: " +
        "procs=$procs2 populated=" + (Populated $cg2)) ($procs2 -eq "0" -and (Populated $cg2) -eq "1")
    ReleaseHold 2
    Check "without its hold and with the container, cgroup 2 reads populated 1" ((Populated $cg2) -eq "1")
    & podman stop ko-agent-bpf-below | Out-Null
    Check "after the container's stop, cgroup 2 reads populated 0" ((Populated $cg2) -eq "0")
    function WaitRemoved([string]$cgroup, [int]$seconds) {
        (Vm ("t0=`$(date +%s%N); for i in `$(seq 1 " + ($seconds * 10) + "); do test -d $cgroup || " +
            "{ echo removed_after_ms=`$(( (`$(date +%s%N) - t0) / 1000000 )); exit 0; }; sleep 0.1; done; " +
            "echo still_present_after_ms=" + ($seconds * 1000))).Trim()
    }
    Info ("cgroup 2 without its hold or a container: " + (WaitRemoved $cg2 60))
    Info (Vm "sudo -n $Ctl link-info $PinRoot/2/file_open")
    RemoveCgroup 2
    Info ("cgroup 2 after its removal: " + (WaitRemoved $cg2 10))
    $after = Vm "sudo -n $Ctl link-info $PinRoot/2/file_open"
    Info $after
    Check "the pinned link outlives the cgroup with cgroup_id 0, detached without an error" `
        ((Field "cgroup_id" $before) -ne "0" -and (Field "cgroup_id" $after) -eq "0")
    Vm "sudo -n $Ctl unpin $PinRoot/2" | Out-Null

    # -----------------------------------------------------------------------
    Step "the container's own cgroup: podman create, podman init, attach, podman start"
    # -----------------------------------------------------------------------
    # A guarded launch, the launcher's sequence: create, init, attach to the container's own
    # cgroup, read from its init process (a `libpod-<id>.scope` under systemd, a `<id>` directory
    # under cgroupfs), then start only when the controller succeeded; otherwise unpin and leave the
    # container initialized. The same function runs with and without an injected controller failure.
    function GuardedLaunch([string]$name, [string]$pinDir, [string]$controllerOption) {
        & podman rm -f $name 2>&1 | Out-Null
        & podman create --name $name --userns=keep-id --volume "${Fix}:${FixVm}" $Image `
            sh -c "echo STARTED; (echo x >> $MarkerPath) 2>&1 && echo WRITE_OK || echo WRITE_FAIL" | Out-Null
        & podman init $name | Out-Null
        $launchPid = (& podman inspect --format '{{.State.Pid}}' $name)
        $script:launchCg = (Vm "sed -n 's|^0::|/sys/fs/cgroup|p' /proc/$launchPid/cgroup").Trim()
        $state = & podman inspect --format '{{.State.Status}}' $name
        Info "after podman init: state=$state pid=$launchPid cgroup=$script:launchCg"
        $procs = Vm ("for p in `$(cat $script:launchCg/cgroup.procs $script:launchCg/*/cgroup.procs 2>/dev/null); " +
            "do printf '%s(%s) ' `$p `$(cat /proc/`$p/comm); done")
        Info ("processes in it: " + $procs.Trim())
        $script:launchAttach = Vm "sudo -n $Ctl attach $script:launchCg $pinDir $controllerOption file_open"
        if ($script:vmStatus -eq 0) {
            $script:launchOutput = (& podman start --attach $name 2>&1 | ForEach-Object { "$_" }) -join "`n"
            Add-Content -Path $Transcript -Value $script:launchOutput -Encoding UTF8
        } else {
            $script:launchOutput = ""
            Vm "sudo -n $Ctl unpin $pinDir" | Out-Null
        }
        $script:launchStatus = (& podman inspect --format '{{.State.Status}}' $name)
    }
    GuardedLaunch "ko-agent-bpf-scope" "$PinRoot/3" ""
    Check "the container's cgroup exists after podman init" ($script:launchCg -ne "")
    Check "file_open attached to the container's cgroup before start" ((Field "ok" $script:launchAttach) -eq "1")
    Check "started under its cgroup's policy: the command ran and the marker is refused for writing" `
        ((Has "STARTED" $script:launchOutput) -and (Has "WRITE_FAIL" $script:launchOutput))
    & podman rm ko-agent-bpf-scope | Out-Null
    Info (Vm "sudo -n $Ctl link-info $PinRoot/3/file_open")
    Vm "sudo -n $Ctl unpin $PinRoot/3" | Out-Null

    # -----------------------------------------------------------------------
    Step "a failed attach starts no container"
    # -----------------------------------------------------------------------
    # The same launch with the controller failing after its attach, as a read-back mismatch would.
    GuardedLaunch "ko-agent-bpf-closed" "$PinRoot/4" "--fail-after-attach"
    Check "the controller attached and then reported the injected failure" `
        ((Field "ok" $script:launchAttach) -eq "1" -and (Has "injected failure" $script:launchAttach))
    Check "the container was never started: status=$script:launchStatus, nothing printed" `
        ($script:launchStatus -eq "initialized" -and -not (Has "STARTED" $script:launchOutput))
    & podman rm -f ko-agent-bpf-closed | Out-Null

    # -----------------------------------------------------------------------
    Step "a createContainer hook under the attach cgroup: its cgroup, and its write of the marker"
    # -----------------------------------------------------------------------
    # The OCI runtime spec leaves a createContainer hook's cgroup open ("Lifecycle", 1): the hook
    # records its own and tries the marker. The machine's podman runs the container, since
    # --hooks-dir is a global option of the podman that runs the runtime, not of the remote client;
    # --cgroupns=host keeps /proc/self/cgroup a full path, which a private cgroup namespace would
    # cut at the container's.
    $hooks = "$homeVm/$MachineDir/hooks"
    function Base64([string]$text) { [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($text)) }
    $hookScript = @(
        "#!/bin/sh",
        "# The Phase 1 probe's createContainer hook: it records where it runs and whether the marker opens.",
        "{ echo cgroup=`$(sed -n 's/^0:://p' /proc/self/cgroup)",
        "  if err=`$( (echo x >> $MarkerPath) 2>&1 ); then echo write=ok; else echo `"write=fail error=`$err`"; fi",
        "} > $hooks/hook.out 2>&1"
    ) -join "`n"
    $hookJson = "{`"version`": `"1.0.0`", `"hook`": {`"path`": `"$hooks/hook.sh`"}, `"when`": {`"always`": true}, " +
        "`"stages`": [`"createContainer`"]}"
    Vm ("mkdir -p $hooks; rm -f $hooks/hook.out; echo '" + (Base64 $hookScript) + "' | base64 -d > $hooks/hook.sh; " +
        "chmod +x $hooks/hook.sh; echo '" + (Base64 $hookJson) + "' | base64 -d > $hooks/hook.json") | Out-Null
    $hookRun = Vm ("podman --hooks-dir $hooks run --rm --cgroupns=host --cgroup-parent=$parent1 --userns=keep-id " +
        "--volume ${FixVm}:${FixVm} $Image echo CONTAINER_RAN")
    $hookOut = Vm "cat $hooks/hook.out 2>&1"
    Info ("hook: " + $hookOut.Replace("`n", " "))
    Check "the hook ran and the container started" ((Has "cgroup=" $hookOut) -and (Has "CONTAINER_RAN" $hookRun))
    $hookCg = ""
    foreach ($line in $hookOut -split "`n") { if ($line -match '^cgroup=(.*)$') { $hookCg = $Matches[1] } }
    $cg1Rel = $cg1.Substring("/sys/fs/cgroup".Length)
    Check "the hook ran below attach cgroup 1: $hookCg" ($cg1Rel -ne "" -and $hookCg.StartsWith($cg1Rel))
    Check "the hook's write of the marker is refused with EPERM" `
        ((Has "write=fail" $hookOut) -and (Has "not permitted" $hookOut))

    # -----------------------------------------------------------------------
    Step "the barrier in the jited program, and the walk's counters"
    # -----------------------------------------------------------------------
    $jited = Vm "sudo -n $Ctl jited $PinRoot/1/file_open /tmp/file_open.jited"
    Info $jited
    $b64 = (Vm "base64 -w0 /tmp/file_open.jited").Trim()
    try {
        [IO.File]::WriteAllBytes((Join-Path $OutDir "file_open.jited"), [Convert]::FromBase64String($b64))
    } catch {}
    $barrier = (Field "ldaddal" $jited) -ne "0" -or (Field "dmb_ish" $jited) -ne "0" -or
        (Field "lock_xadd" $jited) -ne "0"
    Check "the xlated program holds the atomic fetch-add and the jited one a barrier instruction" `
        ((Field "fetch_add_insns" $jited) -ne "" -and (Field "fetch_add_insns" $jited) -ne "0" -and $barrier)
    $stats = Vm "sudo -n $Ctl stats $PinRoot/1/file_open"
    foreach ($line in $stats -split "`n") { if ($line -match 'hook=file_open') { Log $line } }
    Set-Content -Path (Join-Path $OutDir "stats.txt") -Value $stats -Encoding UTF8
} finally {
    Cleanup
}
if ($script:failed -ne 0) { exit 1 }
