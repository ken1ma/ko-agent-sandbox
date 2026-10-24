# phase4.sh for a Windows host: the same rows on the WSL podman machine. Run it in PowerShell, from
# anywhere, with the default machine running:
#
#     ...\bpf\probe\phase4\phase4.ps1 [OUTDIR]
#
# It needs %UserProfile%\.wslconfig holding `[wsl2]` and `isolateDistroCgroup=false`
# (doc/plan-bpf-lsm-cgroup.md, "Environment evidence"), or the containers land in no cgroup of
# their own. The fixtures are under %UserProfile%\.cache, which the machine serves under /mnt/<drive>
# (SandboxWorkspace.mountPathOf); the containers mount them with the Windows path as the source.
# Under the machine's cgroupfs manager the attach cgroup is a directory under the user's delegated
# subtree, the proof process joins a leaf below it from a transient scope of the user manager, and
# the reconcile removes the directory itself.
# The rows, what they leave behind and where the output goes are phase4.sh's, the output under
# out-wsl\ beside this script, so that a copy of it to the macOS checkout sits beside the macOS
# driver's out-macos\.
param([string]$OutDir = "")

$ErrorActionPreference = "Continue"
$ProbeImage = "ko-agent-bpf-probe:phase4"
$MachineDir = ".local/share/ko-agent-sandbox/bpf-probe4"
$Ctl = "./$MachineDir/controller"
$Rb = "./$MachineDir/readback"
$Fxt = "./$MachineDir/fixture"
$FxtC = "/out/fixture"
$Tags = "./$MachineDir/tags.txt"
$PinRoot = "/sys/fs/bpf/ko-agent-bpf-phase4"
$Vol = "ko-agent-bpf4-vol"
$Label = "ko-agent-bpf4.session"
$LabelCg = "ko-agent-bpf4.cgroup"
$Hooks8 = "file_open inode_create inode_mknod inode_symlink inode_link inode_rename inode_unlink inode_setattr"
$Hooks9 = "$Hooks8 file_receive"
$Hooks7 = "file_open inode_create inode_mknod inode_symlink inode_link inode_rename inode_unlink"
$ProbeDir = $PSScriptRoot
$RepoDir = (Resolve-Path (Join-Path $ProbeDir "..\..\..")).Path
if ($OutDir -eq "") { $OutDir = Join-Path $ProbeDir "out-wsl" }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$OutDir = (Resolve-Path $OutDir).Path
$Transcript = Join-Path $OutDir "transcript.log"
Set-Content -Path $Transcript -Value "" -Encoding UTF8

$Fix = Join-Path $env:USERPROFILE (".cache\ko-agent-bpf-phase4." + $PID)
function MachinePath([string]$windowsPath) {
    "/mnt/" + $windowsPath.Substring(0, 1).ToLower() + "/" + $windowsPath.Substring(3).Replace("\", "/")
}
$FixVm = MachinePath $Fix
$Tree = "$FixVm/tree"
$Proof = "$FixVm/state/proof"
$RulesA = "$FixVm/rules-a.txt"
$RulesB = "$FixVm/rules-b.txt"
$RecA = "$FixVm/records-a.bin"
$RecB = "$FixVm/records-b.bin"
$script:RecCurrent = $RecA
$script:RulesCurrent = $RulesA
$script:ProofLaid = $RulesA
$script:ProofDirty = $false

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
function Lines([string]$text, [string]$pattern) { ($text -split "`n" | Where-Object { $_ -match $pattern }) -join "`n" }
function Indent([string]$text) {
    if ($text -ne "") { Log (($text -split "`n" | ForEach-Object { "  $_" }) -join "`n") }
}
function Step([string]$text) { Log ""; Log "== $text" }
function State([string]$name) { (& podman inspect --format '{{.State.Status}}' $name 2>$null | Out-String).Trim() }
function Running([string]$name) { (& podman inspect --format '{{.State.Running}}' $name 2>$null | Out-String).Trim() }
function Verdict([string]$text) {
    $line = Lines $text "ok=0"
    if ($line.Length -gt 70) { $line.Substring(0, 70) } else { $line }
}

function Cleanup {
    Step "cleanup"
    $ids = & podman ps -aq --filter "label=$Label" 2>&1
    if ($ids) { & podman rm -f @ids 2>&1 | Out-Null }
    Vm ("sudo -n umount $PinRoot/r4 2>/dev/null; sudo -n umount $Tree/vendor 2>/dev/null; " +
        "[ -x $Ctl ] && sudo -n sh -c 'for d in $PinRoot/*; do [ -e `$d ] && $Ctl unpin `$d; done'; " +
        "sudo -n rmdir $PinRoot 2>/dev/null; " +
        "systemctl --user stop 'ko-agent-bpf4-*' 2>/dev/null; systemctl --user reset-failed 2>/dev/null; " +
        "rmdir /sys/fs/cgroup/user.slice/user-*.slice/user@*.service/app.slice/ko-agent-bpf4-*/proof 2>/dev/null; " +
        "rmdir /sys/fs/cgroup/user.slice/user-*.slice/user@*.service/app.slice/ko-agent-bpf4-* 2>/dev/null; " +
        "rm -rf $MachineDir/sessions; true") | Out-Null
    & podman volume rm -f $Vol 2>&1 | Out-Null
    Vm "rm -rf $FixVm" | Out-Null
    if (Test-Path $Fix) { Remove-Item -Recurse -Force $Fix -ErrorAction SilentlyContinue }
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
    $UidVm = (Vm "id -u").Trim()
    $KernelVm = (Vm "uname -r").Trim()
    $Manager = (Vm "podman info --format '{{.Host.CgroupManager}}'").Trim()
    $Runtime = ((Vm "podman info --format '{{.Host.OCIRuntime.Name}} {{.Host.OCIRuntime.Version}}'") -split "`n")[0]
    Info ("machine user uid=$UidVm kernel=$KernelVm podman=$(& podman --version) cgroup manager=$Manager " +
        "runtime=$Runtime")
    function MountFs {
        Vm ("sudo -n sh -c 'findmnt -n /sys/kernel/security >/dev/null || mount -t securityfs securityfs " +
            "/sys/kernel/security'; sudo -n sh -c 'findmnt -n /sys/fs/bpf >/dev/null || mount -t bpf " +
            "bpf /sys/fs/bpf'") | Out-Null
    }
    MountFs
    Info "lsm=$(Vm 'sudo -n cat /sys/kernel/security/lsm')"
    Vm "rm -rf $FixVm" | Out-Null
    New-Item -ItemType Directory -Force -Path $Fix | Out-Null
    $findmnt = Vm "findmnt -T $FixVm -o TARGET,SOURCE,FSTYPE,OPTIONS"
    Set-Content -Path (Join-Path $OutDir "findmnt.txt") -Value $findmnt -Encoding UTF8
    $FsType = (Vm "findmnt -T $FixVm -n -o FSTYPE").Trim()
    Info "share: $(($findmnt -split "`n")[1]), type $FsType"
    Vm "sudo -n mkdir -p $PinRoot" | Out-Null
    $SliceRoot = "/sys/fs/cgroup/user.slice/user-$UidVm.slice"
    $AppSlice = "/user.slice/user-$UidVm.slice/user@$UidVm.service/app.slice"

    # -----------------------------------------------------------------------
    Step "build, with the hash of its sources, and install"
    # -----------------------------------------------------------------------
    $Ctx = Join-Path $Fix "build-context"
    New-Item -ItemType Directory -Force -Path $Ctx | Out-Null
    $sources = New-Object IO.MemoryStream
    foreach ($name in Get-Content (Join-Path $ProbeDir "sources.txt")) {
        if ($name.Trim() -eq "") { continue }
        $file = Join-Path $ProbeDir $name
        Copy-Item $file (Join-Path $Ctx (Split-Path -Leaf $file))
        $bytes = [IO.File]::ReadAllBytes($file)
        $sources.Write($bytes, 0, $bytes.Length)
    }
    $digest = [Security.Cryptography.SHA256]::Create().ComputeHash($sources.ToArray())
    $SourcesSha = ([BitConverter]::ToString($digest) -replace "-", "").ToLower()
    Info "sources sha256=$SourcesSha over $((Get-Content (Join-Path $ProbeDir 'sources.txt')) -join ' ')"
    # The procedure's digest, the two drivers and the rule defaults, says which measurement ran; it
    # binds nothing, since the plan's sections name the compiled sources' hash alone.
    $procedure = New-Object IO.MemoryStream
    foreach ($file in @((Join-Path $ProbeDir "phase4.sh"), (Join-Path $ProbeDir "phase4.ps1"),
                        (Join-Path $RepoDir "src\main\resources\agentsandbox\file-rule-defaults"))) {
        $bytes = [IO.File]::ReadAllBytes($file)
        $procedure.Write($bytes, 0, $bytes.Length)
    }
    $digest = [Security.Cryptography.SHA256]::Create().ComputeHash($procedure.ToArray())
    $ProcedureSha = ([BitConverter]::ToString($digest) -replace "-", "").ToLower()
    Info "procedure sha256=$ProcedureSha over phase4.sh phase4.ps1 file-rule-defaults"
    & podman build --build-arg "BUILD_KERNEL=$KernelVm" -t $ProbeImage -f (Join-Path $Ctx "Containerfile") $Ctx 2>&1 |
        ForEach-Object { "$_" } | Add-Content -Path $Transcript -Encoding UTF8
    if ($LASTEXITCODE -ne 0) { Log "the probe image failed to build; the build log is in $Transcript"; exit 2 }
    Vm ("set -eu; mkdir -p $MachineDir; podman create --replace --name ko-agent-bpf4-extract $ProbeImage " +
        ">/dev/null; podman cp ko-agent-bpf4-extract:/out/. $MachineDir/; podman rm ko-agent-bpf4-extract " +
        ">/dev/null; cp $MachineDir/policy.bpf.o $MachineDir/policy-installed.bpf.o; " +
        "test -x $MachineDir/controller && test -x $MachineDir/readback && test -x $MachineDir/fixture") | Out-Null
    Check "probe installed in the machine" ($script:vmStatus -eq 0)
    $leftover = Lines (Vm ("sudo -n sh -c 'ls $PinRoot; for d in $PinRoot/*; do [ -e `$d ] && " +
        "$Ctl unpin `$d; done'")) "^(?!unpinned)."
    if ($leftover -ne "") { Info "pins left by an earlier run, removed: $($leftover -replace "`n", ' ')" }
    $build = "sources sha256=$SourcesSha`nprocedure sha256=$ProcedureSha`n" +
        (Vm "cat $MachineDir/clang-version.txt $MachineDir/build-kernel.txt $MachineDir/objects.sha256")
    Set-Content -Path (Join-Path $OutDir "build.txt") -Value $build -Encoding UTF8
    Info ($build -replace "`n", " ")
    $tagsOut = Vm "sudo -n $Rb tags policy.bpf.o $Tags"
    Info (Lines $tagsOut "^tags ")
    Check "the installed object's nine tags are recorded" ((Field "programs" $tagsOut) -eq "9")

    # -----------------------------------------------------------------------
    Step "the workspace fixture, the proof fixture, the records and the volume"
    # -----------------------------------------------------------------------
    $defaults = Get-Content (Join-Path $RepoDir "src\main\resources\agentsandbox\file-rule-defaults") |
        ForEach-Object { ($_ -replace "#.*", "").Trim() } | Where-Object { ($_ -split "\s+").Count -eq 2 } |
        ForEach-Object { ($_ -split "\s+") -join " " }
    # PowerShell reads variable names without case: these hold the text, $RulesA and $RulesB the paths.
    $rulesTextB = ($defaults -join "`n") + "`n"
    $rulesTextA = $rulesTextB + "writable .vscode/settings.json`n"
    [IO.File]::WriteAllText((Join-Path $Fix "rules-a.txt"), $rulesTextA)
    [IO.File]::WriteAllText((Join-Path $Fix "rules-b.txt"), $rulesTextB)
    $Guarded = "--guarded workspace= --guarded guarded-git=.git --guarded guarded-sandbox=.ko-agent-sandbox"
    $made = Vm ("$Fxt make $Tree $RulesA && mkdir -p $FixVm/state && $Fxt make $Proof $RulesA && " +
        "$Fxt records $RulesA $RecA $Guarded && $Fxt records $RulesB $RecB $Guarded")
    Indent $made
    Check "the workspace fixture, the proof fixture and two records files exist" `
        ((Count "make " $made) -eq 2 -and (Count "records " $made) -eq 2)
    & podman volume create $Vol 2>&1 | Out-Null
    $VolMp = (Vm "podman volume inspect --format '{{.Mountpoint}}' $Vol").Trim()
    Info "the volume's mountpoint in the machine: $VolMp, on $(Vm "findmnt -T $VolMp -n -o FSTYPE")"
    $SessionOpts = @("--userns=keep-id", "--security-opt", "seccomp=unconfined", "--volume", "${Fix}:$FixVm",
        "--volume", "${Vol}:/vol")
    $SessionCmd = "echo STARTED; $FxtC write $Tree/.git/config; $FxtC write $Tree/ordinary; exec sleep infinity"
    $ExpectA = "--tags $Tags --records $RecA --workspace $Tree --fixture $Proof --volume $VolMp"
    $ExpectB = "--tags $Tags --records $RecB --workspace $Tree --fixture $Proof --volume $VolMp"

    # -----------------------------------------------------------------------
    # The launcher's steps, as functions
    # -----------------------------------------------------------------------
    function AttachCgroup([string]$name) {
        if ($Manager -eq "systemd") {
            Vm ("systemctl --user stop ko-agent-bpf4-hold-$name 2>/dev/null; systemctl --user reset-failed " +
                "2>/dev/null; systemd-run --user --unit=ko-agent-bpf4-hold-$name --slice=ko-agent-bpf4-$name.slice " +
                "/usr/bin/sleep 3600") | Out-Null
            $script:CG = (Vm ("find /sys/fs/cgroup/user.slice -type d -name ko-agent-bpf4-$name.slice " +
                "2>/dev/null | head -1")).Trim()
            $script:PARENT = "ko-agent-bpf4-$name.slice"
        } else {
            $script:PARENT = "$AppSlice/ko-agent-bpf4-$name"
            $script:CG = "/sys/fs/cgroup$($script:PARENT)"
            Vm "mkdir -p $($script:CG)" | Out-Null
        }
        if ($script:CG -eq "") { Fail "no attach cgroup for $name"; $script:CG = "/nonexistent" }
    }
    function ReleaseHold([string]$name) {
        if ($Manager -eq "systemd") { Vm "systemctl --user stop ko-agent-bpf4-hold-$name" | Out-Null }
    }
    function RemoveCgroup([string]$name) {
        if ($Manager -eq "systemd") {
            Vm "systemctl --user stop ko-agent-bpf4-hold-$name ko-agent-bpf4-$name.slice 2>/dev/null; true" | Out-Null
        } else {
            Vm ("rmdir /sys/fs/cgroup$AppSlice/ko-agent-bpf4-$name/proof 2>/dev/null; " +
                "rmdir /sys/fs/cgroup$AppSlice/ko-agent-bpf4-$name") | Out-Null
        }
    }
    function CgroupId([string]$cgPath) { (Vm "stat -c %i $cgPath").Trim() }
    function RecordSession([string]$name, [string]$cgPath) {
        $id = CgroupId $cgPath
        Vm "mkdir -p $MachineDir/sessions && echo 'cgroup=$cgPath cgroup_id=$id' > $MachineDir/sessions/$name" |
            Out-Null
    }
    function ForgetSession([string]$name) { Vm "rm -f $MachineDir/sessions/$name" | Out-Null }
    # The proof, by a process of the launcher's own below the attach cgroup: a scope under the slice,
    # or a leaf directory the process joins.
    function RunProof([string]$cgPath, [string]$parentSlice, [string]$flag) {
        $rules = $script:RulesCurrent
        if ($Manager -eq "systemd") {
            Vm "systemd-run --user --scope --slice=$parentSlice -q $Fxt run $Proof $rules $flag"
        } else {
            # An ssh session's cgroup shares no ancestor the user owns with the delegated subtree, so a
            # transient scope of the user manager comes first and the leaf is joined from there.
            Vm ("mkdir -p $cgPath/proof && systemd-run --user --scope -q sh -c 'echo join " +
                "from=`$(cat /proc/self/cgroup) to=$cgPath/proof; exec $Fxt join $cgPath/proof " +
                "$Fxt run $Proof $rules $flag'; rmdir $cgPath/proof")
        }
    }
    $L = @{}
    function Launch([string]$name, [string]$mode, [string]$ctlOpts, [string]$ctlHooks, [string]$expect = "",
                    [string]$hooks = "") {
        if ($expect -eq "") { $expect = $ExpectA }
        if ($hooks -eq "") { $hooks = $Hooks8 }
        $L.Attach = ""; $L.Check = ""; $L.Verify = ""; $L.Proof = ""; $L.Step = "attach"
        AttachCgroup $name
        $L.Cg = $script:CG
        $L.Parent = $script:PARENT
        $pins = "$PinRoot/$name"
        $reuse = $false
        # The proof fixture is laid out once; its entries are laid out again, the root keeping its
        # identity, only after a failed proof or for other rules ("Lifecycle", 3).
        $rules = $script:RulesCurrent
        if ($script:ProofDirty -or $script:ProofLaid -ne $rules) {
            Vm "find $Proof -mindepth 1 -delete && $Fxt make $Proof $rules" | Out-Null
            $script:ProofLaid = $rules
            $script:ProofDirty = $false
        }
        if ($mode -eq "restart") {
            $L.Check = Vm "sudo -n $Rb check-pins $pins $expect $hooks"
            if (Has " ok=1" $L.Check) { $reuse = $true } else { Vm "sudo -n $Ctl unpin $pins" | Out-Null }
        } else {
            Vm "sudo -n $Ctl unpin $pins" | Out-Null
        }
        if ($reuse) {
            $L.Attach = Vm "sudo -n $Ctl attach-pinned $($L.Cg) $pins $ctlHooks"
        } else {
            $L.Attach = Vm ("sudo -n $Ctl attach $($L.Cg) $pins --records $($script:RecCurrent) --workspace $Tree " +
                "--fixture $Proof --volume $VolMp $ctlOpts $ctlHooks")
        }
        Indent (Lines $L.Attach "^(attach|attach-pinned|refused) ")
        if (-not ($L.Attach -match "(?m)^attach")) { return }
        $L.Step = "verify"
        $L.Verify = Vm "sudo -n $Rb verify $($L.Cg) $expect $hooks"
        Indent $L.Verify
        if (-not (Has "verify ok=1" $L.Verify)) { return }
        $L.Step = "proof"
        $flag = ""
        if ($ctlOpts -like "*unix-sockets*") { $flag = "--unix-sockets" }
        $L.Proof = RunProof $L.Cg $L.Parent $flag
        Indent (Lines $L.Proof "mismatch|^fixture ops")
        if ((Field "mismatches" $L.Proof) -ne "0") { $script:ProofDirty = $true; return }
        $L.Step = "created"
        & podman create --name $name --restart=no "--cgroup-parent=$($L.Parent)" --label "$Label=$name" `
            --label "$LabelCg=$($L.Cg)" @SessionOpts $ProbeImage sh -c $SessionCmd 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) { return }
        RecordSession $name $L.Cg
        & podman start $name 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) { return }
        $L.Step = "started"
    }
    function ExecWrite([string]$name, [string]$path) {
        $out = (& podman exec $name $FxtC write $path 2>&1 | ForEach-Object { "$_" }) -join "`n"
        Add-Content -Path $Transcript -Value $out -Encoding UTF8
        $out
    }
    function WaitLogs([string]$name, [string]$pattern, [int]$count) {
        for ($i = 0; $i -lt 40; $i++) {
            $logs = (& podman logs $name 2>&1 | ForEach-Object { "$_" }) -join "`n"
            if ((Count $pattern $logs) -ge $count) { break }
            Start-Sleep -Milliseconds 500
        }
        $logs = (& podman logs $name 2>&1 | ForEach-Object { "$_" }) -join "`n"
        Add-Content -Path $Transcript -Value $logs -Encoding UTF8
        $logs
    }
    function NoContainer([string]$name) { & podman container exists $name 2>&1 | Out-Null; $LASTEXITCODE -ne 0 }

    # -----------------------------------------------------------------------
    Step "the launch: steps 1 to 4, the first process refused, exec, restart, kill, the controller gone"
    # -----------------------------------------------------------------------
    Launch "s1" "fresh" "" $Hooks8
    Check "the launch ran every step: attach, read-back, proof, create, start (reached $($L.Step))" `
        ($L.Step -eq "started")
    Check "the controller attached eight hooks with $(Field 'rule_count' $L.Attach) rules and five roots, and pinned" `
        ((Field "hooks" $L.Attach) -eq "8" -and (Field "roots" $L.Attach) -eq "5")
    Check "the read-back finds eight programs of the installed tags over one map set holding the records" `
        ((Field "programs" $L.Verify) -eq "8" -and (Field "maps" $L.Verify) -eq "9")
    Check "the proof: $(Lines $L.Proof '^fixture ops')" `
        ((Field "mismatches" $L.Proof) -eq "0" -and [int](Field "ops" $L.Proof) -gt 60)
    $logs = WaitLogs "s1" "result=" 2
    Check "the first process is refused the protected write and makes the ordinary one" `
        ((Has ".git/config result=EPERM" $logs) -and (Has "tree/ordinary result=ok" $logs))
    $CgIdS1 = CgroupId $L.Cg
    Check "the links carry the attach cgroup's identity, its inode number $CgIdS1" `
        ((Field "cgroup_id" $L.Attach) -eq $CgIdS1)
    Check "the controller has exited and no process of it remains while the policy holds" `
        (Has "NONE" (Vm 'pgrep -x controller >/dev/null && echo RUNNING || echo NONE'))
    Check "podman exec joins the container's cgroup and is refused the protected write" `
        (Has "result=EPERM" (ExecWrite "s1" "$Tree/.git/config"))
    $sockCmd = "mkdir -p /tmp/d && $FxtC bind /tmp/d/s; $FxtC rename /tmp/d /vol/d; $FxtC rename /tmp/d $Tree/d"
    $sock = (& podman exec s1 sh -c $sockCmd 2>&1 | ForEach-Object { "$_" }) -join "`n"
    Add-Content -Path $Transcript -Value $sock -Encoding UTF8
    Check "a directory holding a bound socket cannot be renamed into the volume or the workspace: EXDEV" `
        ((Count "result=EXDEV" $sock) -eq 2 -and (Has "bind path=/tmp/d/s result=ok" $sock))
    & podman restart s1 2>&1 | Out-Null
    $logs = WaitLogs "s1" "STARTED" 2
    Check "after podman restart the first process runs again under the policy and is refused again" `
        ((Count "STARTED" $logs) -eq 2 -and (Count ".git/config result=EPERM" $logs) -eq 2)
    & podman kill s1 2>&1 | Out-Null
    Start-Sleep -Seconds 1
    $query = Vm "sudo -n $Ctl query $($L.Cg)"
    $link = Vm "sudo -n $Ctl link-info $PinRoot/s1/links/file_open"
    Check "after podman kill the container is exited and the programs stay attached: $(Field 'prog_cnt' $query)" `
        ((State "s1") -eq "exited" -and (Field "prog_cnt" $query) -eq "8")
    Check "the pinned link still names the cgroup: $link" ((Field "cgroup_id" $link) -eq $CgIdS1)
    Check "the created container's restart policy reads no" `
        ((& podman inspect --format '{{.HostConfig.RestartPolicy.Name}}' s1 | Out-String).Trim() -eq "no")
    & podman start s1 2>&1 | Out-Null
    $rmdirOut = Vm "sudo -n rmdir $($L.Cg) 2>&1 || echo RMDIR_FAILED"
    Check "the attach cgroup cannot be removed while the container is in it: $($rmdirOut -replace "`n", ' ')" `
        (Has "RMDIR_FAILED" $rmdirOut)
    Vm "sudo -n $Ctl unpin $PinRoot/s1" | Out-Null
    $query = Vm "sudo -n $Ctl query $($L.Cg)"
    $afterUnpin = ExecWrite "s1" "$Tree/.git/config"
    Check "root unpinning the links ends the enforcement: 0 programs attached, the protected write succeeds" `
        ((Field "prog_cnt" $query) -eq "0" -and (Has "result=ok" $afterUnpin))
    & podman rm -f s1 2>&1 | Out-Null
    ForgetSession "s1"
    RemoveCgroup "s1"
    $CostAttach = "$(Field 'load_ms' $L.Attach) $(Field 'fill_ms' $L.Attach) $(Field 'attach_ms' $L.Attach)"
    $CostVerify = Field "ms" $L.Verify
    $CostProof = Field "ms" $L.Proof

    # -----------------------------------------------------------------------
    Step "a recreate attaches the pinned programs and loads nothing"
    # -----------------------------------------------------------------------
    Launch "s2" "fresh" "" $Hooks8
    Check "s2 launched fresh (reached $($L.Step))" ($L.Step -eq "started")
    & podman rm -f s2 2>&1 | Out-Null
    RemoveCgroup "s2"
    $link = Vm "sudo -n $Ctl link-info $PinRoot/s2/links/file_open"
    Check "with its cgroup removed the pinned link is detached, cgroup_id 0, and the pinned programs stay" `
        ((Field "cgroup_id" $link) -eq "0" -and
         (Vm "sudo -n test -e $PinRoot/s2/progs/file_open && echo PRESENT").Trim() -eq "PRESENT")
    Launch "s2" "restart" "" $Hooks8
    Check "the recreate checked the pins, attached them to the new cgroup and started (reached $($L.Step))" `
        ((Has "check-pins ok=1" $L.Check) -and $L.Step -eq "started" -and ($L.Attach -match "(?m)^attach-pinned "))
    $logs = WaitLogs "s2" "result=" 2
    Check "the recreated session's first process is refused the protected write" (Has ".git/config result=EPERM" $logs)
    $CostPinned = Field "ms" $L.Attach
    $CostCheck = Field "ms" $L.Check
    & podman rm -f s2 2>&1 | Out-Null
    ForgetSession "s2"
    RemoveCgroup "s2"

    # -----------------------------------------------------------------------
    Step "the three defective controllers, each caught before any container exists"
    # -----------------------------------------------------------------------
    Launch "d1" "fresh" "" $Hooks7
    Check "a controller attaching seven of the eight hooks is caught by the read-back: $(Verdict $L.Verify)" `
        ($L.Step -eq "verify" -and (Field "reason" $L.Verify) -eq "hook-set")
    Check "no container d1 exists" (NoContainer "d1")
    Vm "sudo -n $Ctl unpin $PinRoot/d1" | Out-Null
    RemoveCgroup "d1"
    Launch "d2" "fresh" "--object other.bpf.o" $Hooks8
    Check "a controller attaching another build's programs is caught by their tags: $(Verdict $L.Verify)" `
        ($L.Step -eq "verify" -and (Field "reason" $L.Verify) -eq "tag")
    Check "no container d2 exists" (NoContainer "d2")
    Vm "sudo -n $Ctl unpin $PinRoot/d2" | Out-Null
    RemoveCgroup "d2"
    Launch "d3" "fresh" "--records $RecB" $Hooks8
    Check "a controller loading another rule file's records is caught by the map contents: $(Verdict $L.Verify)" `
        ($L.Step -eq "verify" -and (Field "reason" $L.Verify) -eq "map-contents")
    Check "no container d3 exists" (NoContainer "d3")
    $proofB = RunProof $L.Cg $L.Parent ""
    $script:ProofDirty = $true
    Indent (Lines $proofB "mismatch|^fixture ops")
    Check "the proof fixture catches the wrong records as well: $(Lines $proofB '^fixture ops')" `
        ((Field "mismatches" $proofB) -eq "1")
    Vm "sudo -n $Ctl unpin $PinRoot/d3" | Out-Null
    RemoveCgroup "d3"
    Launch "d4" "fresh" "--object other-data.bpf.o" $Hooks8
    Check "a controller attaching a build differing in data alone: $(Verdict $L.Verify)" `
        ($L.Step -eq "verify" -and (Field "reason" $L.Verify) -eq "rodata")
    Check "no container d4 exists" (NoContainer "d4")
    Vm "sudo -n $Ctl unpin $PinRoot/d4" | Out-Null
    RemoveCgroup "d4"

    # -----------------------------------------------------------------------
    Step "a launch under --unix-sockets: nine hooks, the proof's socket in .git and file_receive"
    # -----------------------------------------------------------------------
    Launch "u1" "fresh" "--flags unix-sockets" $Hooks9 "$ExpectA --flags unix-sockets" $Hooks9
    Check "the launch under unix-sockets ran every step with nine hooks (reached $($L.Step))" `
        ($L.Step -eq "started" -and (Field "programs" $L.Verify) -eq "9")
    Check "the proof refused a socket in .git and a directory descriptor from another mount namespace" `
        ((Has "op=bind path=.git/ko-sock expect=EPERM got=EPERM" $L.Proof) -and
         (Has "op=receive-dir path=. expect=refused got=refused" $L.Proof))
    & podman rm -f u1 2>&1 | Out-Null
    ForgetSession "u1"
    Vm "sudo -n $Ctl unpin $PinRoot/u1" | Out-Null
    RemoveCgroup "u1"

    # -----------------------------------------------------------------------
    Step "pins across a rule change and a new build"
    # -----------------------------------------------------------------------
    Launch "s3" "fresh" "" $Hooks8
    Check "s3 launched fresh (reached $($L.Step))" ($L.Step -eq "started")
    $ProgIdS3 = Field "prog_id" $L.Attach
    & podman rm -f s3 2>&1 | Out-Null
    RemoveCgroup "s3"
    $script:RecCurrent = $RecB
    $script:RulesCurrent = $RulesB
    Launch "s3" "restart" "" $Hooks8 $ExpectB
    Check "after a rule change the pins fail the check and fresh programs are loaded: $(Verdict $L.Check)" `
        ((Field "reason" $L.Check) -eq "map-contents" -and $L.Step -eq "started" -and ($L.Attach -match "(?m)^attach "))
    Check "the fresh programs are new: prog_id $(Field 'prog_id' $L.Attach) after $ProgIdS3" `
        ((Field "prog_id" $L.Attach) -ne $ProgIdS3)
    $ProgIdS3 = Field "prog_id" $L.Attach
    & podman rm -f s3 2>&1 | Out-Null
    RemoveCgroup "s3"
    Vm "cp $MachineDir/other.bpf.o $MachineDir/policy.bpf.o && sudo -n $Rb tags policy.bpf.o $Tags" | Out-Null
    Launch "s3" "restart" "" $Hooks8 $ExpectB
    $script:RecCurrent = $RecA
    $script:RulesCurrent = $RulesA
    Check "after a new build the pins fail the check on their tags and fresh programs are loaded: $(Verdict $L.Check)" `
        ((Field "reason" $L.Check) -eq "tag" -and $L.Step -eq "started" -and ($L.Attach -match "(?m)^attach "))
    Check "the fresh programs are the new build's, prog_id $(Field 'prog_id' $L.Attach) after $ProgIdS3, verified" `
        ((Field "prog_id" $L.Attach) -ne $ProgIdS3 -and (Field "programs" $L.Verify) -eq "8")
    $oldPins = (Vm "sudo -n ls $PinRoot/s3/links $PinRoot/s3/progs | grep -c -v -e '^`$' -e ':`$'").Trim()
    Check "the old pins are gone: the pin directory holds the eight links and eight programs of this launch alone" `
        ($oldPins -eq "16")
    & podman rm -f s3 2>&1 | Out-Null
    ForgetSession "s3"
    Vm "sudo -n $Ctl unpin $PinRoot/s3" | Out-Null
    RemoveCgroup "s3"
    Vm "cp $MachineDir/policy-installed.bpf.o $MachineDir/policy.bpf.o && sudo -n $Rb tags policy.bpf.o $Tags" |
        Out-Null

    # -----------------------------------------------------------------------
    Step "the controller's refusals"
    # -----------------------------------------------------------------------
    AttachCgroup "x1"
    $cgX1 = $script:CG
    function Refusal([string]$arguments) {
        $out = Vm "sudo -n $Ctl $arguments; echo STATUS=`$?"
        (Lines $out "^(refused|STATUS)") -replace "`n", " "
    }
    $common = "--records $RecA --workspace $Tree --fixture $Proof --volume $VolMp"
    $r = Refusal "attach $cgX1 $PinRoot/x1 $common --object /tmp/other.bpf.o $Hooks8"
    Check "an object given as a path is refused: $r" `
        ((Field "reason" $r) -eq "object-path" -and (Field "STATUS" $r) -eq "3")
    $r = Refusal "attach /sys/fs/cgroup/system.slice $PinRoot/x1 $common $Hooks8"
    Check "a cgroup outside the invoking user's slice is refused: $r" `
        ((Field "reason" $r) -eq "cgroup-outside-slice" -and (Field "STATUS" $r) -eq "3")
    Vm "mkdir -p $Tree/vendor && sudo -n mount -t tmpfs tmpfs $Tree/vendor" | Out-Null
    $r = Refusal "attach $cgX1 $PinRoot/x1 $common --bind-source $Tree $Hooks8"
    Check "a mount under the bind source refuses the launch and is named: $r" `
        ((Field "reason" $r) -eq "mount-under-bind-source" -and (Field "STATUS" $r) -eq "3")
    Vm "sudo -n umount $Tree/vendor" | Out-Null
    $r = Refusal "attach $cgX1 $PinRoot/x1 --records $RecA --workspace $Tree --fixture /tmp --volume $VolMp $Hooks8"
    Check "a proof fixture on another filesystem type is refused: $r" `
        ((Field "reason" $r) -eq "fixture-fs-type" -and (Field "STATUS" $r) -eq "3")
    Check "none of the refused attaches pinned anything" `
        ((Vm "sudo -n test -e $PinRoot/x1 && echo PRESENT || echo ABSENT").Trim() -eq "ABSENT")
    RemoveCgroup "x1"

    # -----------------------------------------------------------------------
    Step "the reconcile: orphans, kept sessions, contradictions, cleanup refusals"
    # -----------------------------------------------------------------------
    # A listing or a label read that fails tells the controller so, which then removes nothing;
    # -FailListing makes the listing fail.
    function Reconcile([switch]$FailListing) {
        $records = Vm ("cd $MachineDir/sessions 2>/dev/null && for f in *; do [ -f `$f ] && " +
            "echo `$f `$(cat `$f); done")
        # `podman ps` renders .Labels as text, so the labels are read from each container's inspect. The
        # keys are Go raw strings in backquotes: a double quote inside an argument does not reach a
        # native command from PowerShell 5.1.
        $format = "{{index .Config.Labels ``$Label``}} {{index .Config.Labels ``$LabelCg``}}"
        $listCmd = "podman ps -aq --filter label=$Label"
        if ($FailListing) { $listCmd = "false" }
        $listing = Vm ("ids=`$($listCmd) || exit 9; for id in `$ids; do " +
            "podman inspect --format '$format' `$id || exit 9; done; echo LISTING_OK")
        $ctlArgs = "--manager $Manager"
        $listingFailed = -not (Has "LISTING_OK" $listing)
        $labels = @()
        if ($listingFailed) { $ctlArgs += " --listing-failed" }
        else { $labels = ($listing -split "`n") | Where-Object { $_ -ne "LISTING_OK" } }
        foreach ($line in $records -split "`n") {
            $parts = $line.Trim() -split "\s+"
            if ($parts.Count -lt 3) { continue }
            $name = $parts[0]
            $recordedCg = Field "cgroup" " $line"
            $id = Field "cgroup_id" " $line"
            $named = ""
            foreach ($entry in $labels) {
                $pair = $entry.Trim() -split "\s+"
                if ($pair.Count -ge 2 -and $pair[0] -eq $name) { $named = $pair[1] }
            }
            if ($named -eq "") { if (-not $listingFailed) { ReleaseHold $name } }
            elseif ($named -eq $recordedCg) { $ctlArgs += " --named $name" }
            else { $ctlArgs += " --hold $name" }
            $ctlArgs += " --session $name $recordedCg $id"
        }
        Start-Sleep -Seconds 1
        $script:ROut = Vm "sudo -n $Ctl reconcile $PinRoot $ctlArgs"
        Indent $script:ROut
        foreach ($line in $script:ROut -split "`n") {
            if ($line -match "cgroup=stop-slice slice=(\S+)") { Vm "systemctl --user stop $($Matches[1])" | Out-Null }
            if ($line -match "^reconcile session=(\S+) action=removed") { ForgetSession $Matches[1] }
        }
    }
    function ActionOf([string]$name) {
        if ($script:ROut -match "(?m)^reconcile session=$name action=(\S+)") { $Matches[1] } else { "" }
    }
    function ReasonOf([string]$name) {
        if ($script:ROut -match "(?m)^reconcile session=$name .*reason=(\S+)") { $Matches[1] } else { "" }
    }
    AttachCgroup "o1"
    Vm "sudo -n $Ctl attach $($script:CG) $PinRoot/o1 $common $Hooks8" | Out-Null
    RecordSession "o1" $script:CG
    AttachCgroup "o2"
    Vm "sudo -n $Ctl attach $($script:CG) $PinRoot/o2 $common $Hooks8" | Out-Null
    RecordSession "o2" $script:CG
    & podman create --name o2 "--cgroup-parent=$($script:PARENT)" --label "$Label=o2" --label "$LabelCg=$($script:CG)" `
        localhost/ko-agent-bpf4-no-such-image:none true 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) { Fail "podman create of a missing image worked" }
    AttachCgroup "o3"
    Vm "sudo -n $Ctl attach $($script:CG) $PinRoot/o3 $common $Hooks8" | Out-Null
    RecordSession "o3" $script:CG
    & podman create --name o3 --restart=no "--cgroup-parent=$($script:PARENT)" --label "$Label=o3" `
        --label "$LabelCg=$($script:CG)" @SessionOpts $ProbeImage sh -c $SessionCmd 2>&1 | Out-Null
    Launch "st" "fresh" "" $Hooks8
    & podman kill st 2>&1 | Out-Null
    Launch "lv" "fresh" "" $Hooks8
    Check "the reconcile's sessions exist: o1, o2, o3, st stopped, lv live" `
        ((State "st") -eq "exited" -and (State "lv") -eq "running")
    Reconcile -FailListing
    Check "a listing that fails removes nothing: $(Lines $script:ROut '^reconcile listing')" `
        ((Field "removed" $script:ROut) -eq "0" -and (Has "listing=failed" $script:ROut))
    Reconcile
    Check "the two orphans are removed, pins and cgroups: o1 $(ActionOf 'o1'), o2 $(ActionOf 'o2')" `
        ((ActionOf "o1") -eq "removed" -and (ActionOf "o2") -eq "removed")
    Check "o3 (created), st (stopped) and lv (live) stay: $(ActionOf 'o3') $(ActionOf 'st') $(ActionOf 'lv')" `
        ((ActionOf "o3") -eq "kept" -and (ActionOf "st") -eq "kept" -and (ActionOf "lv") -eq "kept")
    Check "nothing else was removed: $(Lines $script:ROut '^reconcile sessions')" `
        ((Field "removed" $script:ROut) -eq "2")
    $gone = (Vm "sudo -n ls -d $PinRoot/o1 $PinRoot/o2 2>/dev/null | wc -l").Trim()
    $stay = (Vm "sudo -n ls -d $PinRoot/o3 $PinRoot/st 2>/dev/null | wc -l").Trim()
    Check "o1's and o2's pins and cgroups are gone, o3's and st's stay" ($gone -eq "0" -and $stay -eq "2")
    & podman rm o3 2>&1 | Out-Null
    Reconcile
    Check "once its container is removed, o3's pins and cgroup go: $(ActionOf 'o3')" ((ActionOf "o3") -eq "removed")
    AttachCgroup "c1"
    Vm "sudo -n $Ctl attach $($script:CG) $PinRoot/c1 $common $Hooks8" | Out-Null
    RecordSession "c1" $script:CG
    & podman create --name c1 "--cgroup-parent=$($script:PARENT)" --label "$Label=c1" --label "$LabelCg=/elsewhere" `
        $ProbeImage true 2>&1 | Out-Null
    AttachCgroup "c2"
    Vm "sudo -n $Ctl attach $($script:CG) $PinRoot/c2 $common $Hooks8" | Out-Null
    RecordSession "c2" $script:CG
    $c2Id = CgroupId $script:CG
    RemoveCgroup "c2"
    AttachCgroup "c2"
    Info "c2's cgroup recreated at its path: identity $c2Id before, $(CgroupId $script:CG) after"
    AttachCgroup "c3"
    Vm "sudo -n $Ctl attach $($script:CG) $PinRoot/c3 $common $Hooks8" | Out-Null
    AttachCgroup "c4"
    Vm "sudo -n mv $PinRoot/c3 $PinRoot/c4" | Out-Null
    RecordSession "c4" $script:CG
    Reconcile
    Check "a container whose label names another cgroup leaves c1 unassociated: $(ActionOf 'c1') $(ReasonOf 'c1')" `
        ((ActionOf "c1") -eq "kept" -and (ReasonOf "c1") -eq "identity-contradicted")
    Check "a cgroup whose identity changed is refused: $(ActionOf 'c2') $(ReasonOf 'c2')" `
        ((ActionOf "c2") -eq "refused" -and (ReasonOf "c2") -eq "cgroup-identity")
    Check "a pin directory whose links name another cgroup is refused: $(ActionOf 'c4') $(ReasonOf 'c4')" `
        ((ActionOf "c4") -eq "refused" -and (ReasonOf "c4") -eq "pin-names-another-cgroup")
    Check "nothing was removed for them" ((Field "removed" $script:ROut) -eq "0")
    & podman rm -f c1 2>&1 | Out-Null
    Vm ("sudo -n $Ctl unpin $PinRoot/c1; sudo -n $Ctl unpin $PinRoot/c2; sudo -n $Ctl unpin $PinRoot/c4; " +
        "rm -f $MachineDir/sessions/c1 $MachineDir/sessions/c2 $MachineDir/sessions/c4") | Out-Null
    RemoveCgroup "c1"
    RemoveCgroup "c2"
    RemoveCgroup "c3"
    RemoveCgroup "c4"
    # A refusal removes nothing: c5's links hold one of c6's among their own, and c7's progs directory
    # is a symlink; every pin of both must survive the reconcile.
    AttachCgroup "c5"
    Vm "sudo -n $Ctl attach $($script:CG) $PinRoot/c5 $common $Hooks8" | Out-Null
    RecordSession "c5" $script:CG
    AttachCgroup "c6"
    Vm "sudo -n $Ctl attach $($script:CG) $PinRoot/c6 $common $Hooks8" | Out-Null
    Vm "sudo -n mv $PinRoot/c6/links/inode_setattr $PinRoot/c5/links/zz-foreign" | Out-Null
    AttachCgroup "c7"
    Vm "sudo -n $Ctl attach $($script:CG) $PinRoot/c7 $common $Hooks8" | Out-Null
    RecordSession "c7" $script:CG
    Vm "sudo -n mv $PinRoot/c7/progs $PinRoot/c7/progs-real && sudo -n ln -s progs-real $PinRoot/c7/progs" | Out-Null
    Reconcile
    function PinsOf([string]$name, [string]$sub) {
        (Vm "sudo -n sh -c 'ls $PinRoot/$name/$sub 2>/dev/null | wc -l'").Trim()
    }
    Check "one foreign link among a session's pins refuses it: $(ActionOf 'c5') $(ReasonOf 'c5')" `
        ((ActionOf "c5") -eq "refused" -and (ReasonOf "c5") -eq "pin-names-another-cgroup")
    Check "and every pin of c5 survives: $(PinsOf 'c5' 'links') links, $(PinsOf 'c5' 'progs') programs" `
        ((PinsOf "c5" "links") -eq "9" -and (PinsOf "c5" "progs") -eq "8")
    Check "a progs directory that is a symlink refuses the session: $(ActionOf 'c7') $(ReasonOf 'c7')" `
        ((ActionOf "c7") -eq "refused" -and (ReasonOf "c7") -eq "pins-open")
    Check "and every link of c7 survives: $(PinsOf 'c7' 'links') links" ((PinsOf "c7" "links") -eq "8")
    Vm ("sudo -n rm $PinRoot/c7/progs && sudo -n mv $PinRoot/c7/progs-real $PinRoot/c7/progs; " +
        "sudo -n $Ctl unpin $PinRoot/c5; sudo -n $Ctl unpin $PinRoot/c6; sudo -n $Ctl unpin $PinRoot/c7; " +
        "rm -f $MachineDir/sessions/c5 $MachineDir/sessions/c7") | Out-Null
    RemoveCgroup "c5"
    RemoveCgroup "c6"
    RemoveCgroup "c7"
    AttachCgroup "r1"
    ReleaseHold "r1"
    $r1Cg = $script:CG
    $r1Id = [long](CgroupId $r1Cg)
    $r = Vm ("sudo -n $Ctl reconcile $PinRoot --manager $Manager --session ../r1 $r1Cg $r1Id " +
        "--session r1 $SliceRoot/../r1 $r1Id")
    Indent $r
    Check "a session name and a cgroup path with a relative component are refused" `
        ((Count "action=refused reason=name" $r) -eq 1 -and
         (Count "action=refused reason=cgroup-outside-slice" $r) -eq 1)
    $symlink = Vm "sudo -n mkdir -p $PinRoot/real && sudo -n ln -s $PinRoot/real $PinRoot/r2 2>&1 && echo LINKED"
    if (Has "LINKED" $symlink) {
        $r = Vm "sudo -n $Ctl reconcile $PinRoot --manager $Manager --session r2 $r1Cg $r1Id"
        Indent $r
        Check "a symlink in place of the pin directory is refused: $(Lines $r 'session=r2')" `
            (Has "session=r2 action=refused reason=pins-open" $r)
        Vm "sudo -n rm $PinRoot/r2; sudo -n rmdir $PinRoot/real" | Out-Null
    } else {
        Info "bpffs refused the symlink: $($symlink -replace "`n", ' '); the row is not constructible here"
    }
    $cgSymlink = Vm "ln -s $r1Cg /sys/fs/cgroup$AppSlice/ko-agent-bpf4-r3 2>&1 && echo LINKED || echo REFUSED"
    Info "a symlink in place of a cgroup directory: cgroup2 answers $($cgSymlink -replace "`n", ' ')"
    Vm "sudo -n mkdir -p $PinRoot/r4 && sudo -n mount -t tmpfs tmpfs $PinRoot/r4" | Out-Null
    $r = Vm "sudo -n $Ctl reconcile $PinRoot --manager $Manager --session r4 $r1Cg $r1Id"
    Indent $r
    Check "a mount on the pin directory is refused: $(Lines $r 'session=r4')" `
        (Has "session=r4 action=refused reason=pins-open" $r)
    Vm "sudo -n umount $PinRoot/r4; sudo -n rmdir $PinRoot/r4" | Out-Null
    $r = Vm "sudo -n $Ctl reconcile $PinRoot --manager $Manager --session r1 $r1Cg $($r1Id + 1)"
    Check "a cgroup whose recorded identity differs from the directory's is refused, nothing removed" `
        ((Has "session=r1 action=refused reason=cgroup-identity" $r) -and
         (Vm "test -d $r1Cg && echo PRESENT").Trim() -eq "PRESENT")
    RemoveCgroup "r1"

    # -----------------------------------------------------------------------
    Step "the costs of the launch's steps"
    # -----------------------------------------------------------------------
    Info "install, the verifier over nine programs (tags): $(Field 'ms' $tagsOut) ms"
    Info ("step 2 at launch, the controller: load, fill, attach = $CostAttach ms; step 2 at a recreate, " +
        "attach-pinned: $CostPinned ms after check-pins $CostCheck ms")
    Info "step 3 at launch: read-back $CostVerify ms, proof fixture $CostProof ms ($(Field 'ops' $L.Proof) operations)"

    # -----------------------------------------------------------------------
    Step "a machine restart with a stopped session present: pins, cgroups, and nothing starts it"
    # -----------------------------------------------------------------------
    $answer = ""
    while ($true) {
        Log "The next rows stop the podman machine, which ends every session running on it. Stop it now? [Y/n]"
        $answer = Read-Host
        if ($null -eq $answer) { $answer = "n" }
        if ($answer -in @("", "y", "Y", "yes", "Yes", "YES")) { $answer = "y"; break }
        if ($answer -in @("n", "N", "no", "No", "NO")) { break }
        Log "Answer y or n."
    }
    if ($answer -ne "y") {
        Info "skipped: the machine restart rows were declined"
        & podman rm -f st lv 2>&1 | Out-Null
        ForgetSession "st"
        ForgetSession "lv"
        throw "skip-restart"
    }
    & podman kill lv 2>&1 | Out-Null
    Info "pins before the restart: $((Vm "sudo -n ls $PinRoot") -replace "`n", ' ')"
    Info "podman machine stop at $(Get-Date -Format HH:mm:ss)"
    & podman machine stop 2>&1 | ForEach-Object { "$_" } | Add-Content -Path $Transcript -Encoding UTF8
    Info "podman machine start at $(Get-Date -Format HH:mm:ss)"
    & podman machine start 2>&1 | ForEach-Object { "$_" } | Add-Content -Path $Transcript -Encoding UTF8
    Info "machine started at $(Get-Date -Format HH:mm:ss)"
    for ($i = 0; $i -lt 60; $i++) {
        & podman machine ssh true 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) { break }
        Start-Sleep -Seconds 2
    }
    Start-Sleep -Seconds 15
    MountFs
    Check "after the machine restart no pin survives: $((Vm "sudo -n ls $PinRoot 2>&1") -replace "`n", ' ')" `
        ((Vm "sudo -n test -e $PinRoot && echo PRESENT || echo ABSENT").Trim() -eq "ABSENT")
    Check "the attach cgroups are gone" `
        ((Vm "find /sys/fs/cgroup/user.slice -type d -name 'ko-agent-bpf4-*' 2>/dev/null | wc -l").Trim() -eq "0")
    Check "the stopped containers stay stopped: st $(State 'st'), lv $(State 'lv')" `
        ((Running "st") -eq "false" -and (Running "lv") -eq "false")
    Reconcile
    Check "the reconcile after the restart keeps the sessions with containers: $(ActionOf 'st') $(ActionOf 'lv')" `
        ((ActionOf "st") -eq "kept" -and (ActionOf "lv") -eq "kept")
    & podman rm -f st lv 2>&1 | Out-Null
    ForgetSession "st"
    ForgetSession "lv"
} catch {
    if ("$_" -ne "skip-restart") { throw }
} finally {
    Cleanup
}
if ($script:failed -ne 0) { exit 1 }
