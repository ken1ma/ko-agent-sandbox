# phase3.sh for a Windows host: the same rows on the WSL podman machine. Run it in PowerShell, from
# anywhere, with the default machine running:
#
#     ...\bpf\probe\phase3\phase3.ps1 [OUTDIR]
#
# It needs %UserProfile%\.wslconfig holding `[wsl2]` and `isolateDistroCgroup=false`
# (doc/plan-bpf-lsm-cgroup.md, "Environment evidence"), or the containers land in no cgroup of
# their own. The fixture is under %UserProfile%\.cache, which the machine serves under /mnt/<drive>
# (SandboxWorkspace.mountPathOf); the containers mount it with the Windows path as the source. The
# clone of this repository is made by git in the container, from the repository's /mnt path; the
# second share is the D: drive when the machine serves one; the host-made hard links are NTFS hard
# links, and where NTFS already serves GIT~1 as the pointer file's generated short name, that name
# is the row's second name. One row of its own: the generated short name of `.vscode`, read with
# `dir /x`, written through under the short-names flag. The rows, what they leave behind and where
# the output goes are phase3.sh's, the output under out-wsl\ beside this script, so that a copy
# of it to the macOS checkout sits beside the macOS driver's out-macos\.
param([string]$OutDir = "")

$ErrorActionPreference = "Continue"
$ProbeImage = "ko-agent-bpf-probe:phase3"
$MachineDir = ".local/share/ko-agent-sandbox/bpf-probe3"
$Ctl = "./$MachineDir/controller"
$Exercise = "/out/exercise"
$PinRoot = "/sys/fs/bpf/ko-agent-bpf-phase3"
$Vol = "ko-agent-bpf3-vol"
$Vol2 = "ko-agent-bpf3-home"
$WalkCount = 2000
$WalkPairs = 5
$RaceSeconds = 5
$StormProcs = 16
$StormSeconds = 5
$Hooks8 = "file_open inode_create inode_mknod inode_symlink inode_link inode_rename inode_unlink inode_setattr"
$Hooks9 = "$Hooks8 file_receive"
$ProbeDir = $PSScriptRoot
$RepoDir = (Resolve-Path (Join-Path $ProbeDir "..\..\..")).Path
if ($OutDir -eq "") { $OutDir = Join-Path $ProbeDir "out-wsl" }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$OutDir = (Resolve-Path $OutDir).Path
$Transcript = Join-Path $OutDir "transcript.log"
Set-Content -Path $Transcript -Value "" -Encoding UTF8

$Fix = Join-Path $env:USERPROFILE (".cache\ko-agent-bpf-phase3." + $PID)
function MachinePath([string]$windowsPath) {
    "/mnt/" + $windowsPath.Substring(0, 1).ToLower() + "/" + $windowsPath.Substring(3).Replace("\", "/")
}
$FixVm = MachinePath $Fix
$RepoVm = MachinePath $RepoDir
$Tree = "$FixVm/tree"
$Ptr = "$FixVm/tree-ptr"
$Repo = "$FixVm/repo"
$TreeWin = Join-Path $Fix "tree"
$PtrWin = Join-Path $Fix "tree-ptr"

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
function SumField([string]$key, [string]$text) {
    $sum = 0
    foreach ($line in $text -split "`n") {
        if ($line -match "(^|\s)$key=(\d+)") { $sum += [int]$Matches[2] }
    }
    $sum
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
function Lines([string]$text, [string]$pattern) { ($text -split "`n" | Where-Object { $_ -match $pattern }) -join "`n" }

function Cleanup {
    Step "cleanup"
    & podman rm -f ko-agent-bpf3-srv ko-agent-bpf3-rcv ko-agent-bpf3-slot 2>&1 | Out-Null
    Vm "[ -x $Ctl ] && for d in $PinRoot/*; do sudo -n $Ctl unpin `$d; done; sudo -n rmdir $PinRoot 2>/dev/null; true" |
        Out-Null
    Vm ("systemctl --user stop ko-agent-bpf3-hold1 ko-agent-bpf3-hold2 ko-agent-bpf3-hold3 ko-agent-bpf3-hold4 " +
        "ko-agent-bpf3-1.slice ko-agent-bpf3-2.slice ko-agent-bpf3-3.slice ko-agent-bpf3-4.slice " +
        "2>/dev/null; true") | Out-Null
    Vm ("rmdir /sys/fs/cgroup/user.slice/user-*.slice/user@*.service/app.slice/ko-agent-bpf3-? 2>/dev/null; " +
        "true") | Out-Null
    & podman volume rm -f $Vol $Vol2 2>&1 | Out-Null
    if ($script:Share2Win -and (Test-Path $script:Share2Win)) { Remove-Item -Recurse -Force $script:Share2Win }
    # The machine removes the fixture first: a name the policy let through only unpoliced, such
    # as `.git ` with a trailing space, is one Windows cannot delete.
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
    Vm ("sudo -n sh -c 'findmnt -n /sys/kernel/security >/dev/null || mount -t securityfs securityfs " +
        "/sys/kernel/security'; sudo -n sh -c 'findmnt -n /sys/fs/bpf >/dev/null || mount -t bpf " +
        "bpf /sys/fs/bpf'; sudo -n sh -c 'findmnt -n /sys/kernel/debug >/dev/null || mount -t debugfs " +
        "debugfs /sys/kernel/debug'") | Out-Null
    Info "lsm=$(Vm 'sudo -n cat /sys/kernel/security/lsm')"
    Info ("preemption mode: $(Vm 'sudo -n cat /sys/kernel/debug/sched/preempt 2>/dev/null || echo unavailable'), " +
        "cpus=$(Vm nproc)")
    # The shell's PID names the fixture, so a previous run of this shell may have left one, with
    # names Windows cannot delete; the machine removes it.
    Vm "rm -rf $FixVm" | Out-Null
    New-Item -ItemType Directory -Force -Path $Fix | Out-Null
    $findmnt = Vm "findmnt -T $FixVm -o TARGET,SOURCE,FSTYPE,OPTIONS"
    Set-Content -Path (Join-Path $OutDir "findmnt.txt") -Value $findmnt -Encoding UTF8
    $FsType = (Vm "findmnt -T $FixVm -n -o FSTYPE").Trim()
    Info "share: $(($findmnt -split "`n")[1])"
    Vm "sudo -n mkdir -p $PinRoot" | Out-Null

    # -----------------------------------------------------------------------
    Step "build and install the probe"
    # -----------------------------------------------------------------------
    & podman build --build-arg "BUILD_KERNEL=$KernelVm" -t $ProbeImage $ProbeDir 2>&1 | ForEach-Object { "$_" } |
        Add-Content -Path $Transcript -Encoding UTF8
    if ($LASTEXITCODE -ne 0) { Log "the probe image failed to build; the build log is in $Transcript"; exit 2 }
    Vm ("set -eu; mkdir -p $MachineDir; podman create --replace --name ko-agent-bpf3-extract $ProbeImage " +
        ">/dev/null; podman cp ko-agent-bpf3-extract:/out/. $MachineDir/; podman rm ko-agent-bpf3-extract " +
        ">/dev/null; test -x $MachineDir/controller") | Out-Null
    Check "probe installed in the machine" ($script:vmStatus -eq 0)
    # The sources the object and the binaries were built from, hashed in sources.txt's order: what the
    # plan's section names and bpf/probe/check-evidence.sh recomputes.
    $sources = New-Object IO.MemoryStream
    foreach ($name in Get-Content (Join-Path $ProbeDir "sources.txt")) {
        if ($name.Trim() -eq "") { continue }
        $bytes = [IO.File]::ReadAllBytes((Join-Path $ProbeDir $name))
        $sources.Write($bytes, 0, $bytes.Length)
    }
    $digest = [Security.Cryptography.SHA256]::Create().ComputeHash($sources.ToArray())
    $SourcesSha = ([BitConverter]::ToString($digest) -replace "-", "").ToLower()
    $build = "sources sha256=$SourcesSha`n" +
        (Vm "cat $MachineDir/clang-version.txt $MachineDir/build-kernel.txt $MachineDir/objects.sha256")
    Set-Content -Path (Join-Path $OutDir "build.txt") -Value $build -Encoding UTF8
    Set-Content -Path (Join-Path $OutDir "policy.bpf.asm") -Value (Vm "cat $MachineDir/policy.bpf.asm") -Encoding UTF8
    Info ($build -replace "`n", " ")

    # -----------------------------------------------------------------------
    Step "verifier: the policy program's nine hooks"
    # -----------------------------------------------------------------------
    $load = Vm "sudo -n $Ctl load policy.bpf.o"
    $loadStatus = $script:vmStatus
    Set-Content -Path (Join-Path $OutDir "verifier-policy.txt") -Value $load -Encoding UTF8
    foreach ($line in ($load -split "`n" | Where-Object { $_ -match '^(load|verifier|prog) ' })) { Log "  $line" }
    Check "the policy program's nine hooks load, alone and together" `
        (((Count " ok=1" $load) -eq 10) -and ($loadStatus -eq 0))
    $maxInsns = ($load -split "`n" | ForEach-Object { if ($_ -match 'verified_insns=(\d+)') { [int]$Matches[1] } } |
        Measure-Object -Maximum).Maximum
    Info "the most instructions the verifier processed for one program: $maxInsns, of the limit 1,000,000"
    # The gate's budget ("Phases", 3): a program near the limit fails to load at the next change of the walk.
    Check "every program verifies within 500,000 instructions, half the limit" ([int]$maxInsns -le 500000)
    foreach ($prog in @("inode_rename", "inode_symlink")) {
        $logLine = Vm "sudo -n $Ctl verifier-log policy.bpf.o $prog /tmp/$prog.log"
        Log (Lines $logLine '^verifier ')
        $b64 = Vm "gzip -c /tmp/$prog.log | base64 -w0"
        [IO.File]::WriteAllBytes((Join-Path $OutDir "policy-$prog.log.gz"), [Convert]::FromBase64String($b64.Trim()))
    }
    Info "the logs are in $OutDir\policy-inode_rename.log.gz and policy-inode_symlink.log.gz"

    # -----------------------------------------------------------------------
    Step "fixtures, clone, volume and the attach cgroups"
    # -----------------------------------------------------------------------
    $AppSlice = "/user.slice/user-$UidVm.slice/user@$UidVm.service/app.slice"
    $CG = @{}
    $PARENT = @{}
    foreach ($n in 1..4) {
        if ($Manager -eq "systemd") {
            Vm ("systemctl --user stop ko-agent-bpf3-hold$n 2>/dev/null; systemctl --user reset-failed " +
                "2>/dev/null; systemd-run --user --unit=ko-agent-bpf3-hold$n --slice=ko-agent-bpf3-$n.slice " +
                "/usr/bin/sleep 3600") | Out-Null
            $CG[$n] = (Vm ("find /sys/fs/cgroup/user.slice -type d -name ko-agent-bpf3-$n.slice 2>/dev/null " +
                "| head -1")).Trim()
            $PARENT[$n] = "ko-agent-bpf3-$n.slice"
        } else {
            $PARENT[$n] = "$AppSlice/ko-agent-bpf3-$n"
            $CG[$n] = "/sys/fs/cgroup" + $PARENT[$n]
            Vm "mkdir -p $($CG[$n])" | Out-Null
        }
    }
    Check "four attach cgroups exist under the user's manager: $($CG[1])" `
        (($CG[1] -ne "") -and ($CG[2] -ne "") -and ($CG[3] -ne "") -and ($CG[4] -ne ""))
    & podman volume create $Vol 2>&1 | Out-Null
    & podman volume create $Vol2 2>&1 | Out-Null
    $VolMp = (Vm "podman volume inspect --format '{{.Mountpoint}}' $Vol").Trim()
    $VolFs = (Vm "findmnt -T $VolMp -n -o FSTYPE").Trim()
    Info "the volume's mountpoint in the machine: $VolMp, on $VolFs"
    # The repository is mounted read-only for the clone, which git makes in the container.
    $ExerciserOpts = @("--userns=keep-id", "--security-opt", "seccomp=unconfined", "--volume", "${Fix}:${FixVm}",
        "--volume", "${Vol}:/vol", "--volume", "${Vol2}:/home2", "--volume", "${RepoDir}:${RepoVm}:ro")
    function InCg([int]$n, [string]$script) {
        $out = (& podman run --rm "--cgroup-parent=$($PARENT[$n])" @ExerciserOpts $ProbeImage sh -c $script 2>&1 |
            ForEach-Object { "$_" }) -join "`n"
        Add-Content -Path $Transcript -Value $out -Encoding UTF8
        $out
    }
    function Outside([string]$script) {
        $out = (& podman run --rm @ExerciserOpts $ProbeImage sh -c $script 2>&1 | ForEach-Object { "$_" }) -join "`n"
        Add-Content -Path $Transcript -Value $out -Encoding UTF8
        $out
    }
    function MakeFixture {
        Outside "$Exercise make-tree $Tree" | Out-Null
        # The host-made hard links; NTFS may already serve GIT~1 as the generated short name of
        # `.git`, which is then the second name itself.
        foreach ($pair in @(@(".git", "GIT~1"), @(".ko-agent-sandbox", "KO-AGE~1"))) {
            try {
                New-Item -ItemType HardLink -Path (Join-Path $PtrWin $pair[1]) -Target (Join-Path $PtrWin $pair[0]) `
                    -ErrorAction Stop | Out-Null
            } catch {
                Info "hard link $($pair[1]): $($_.Exception.Message.Trim()); the name NTFS serves stands in"
            }
        }
        New-Item -ItemType HardLink -Path (Join-Path $TreeWin "apps\submod-pointer") `
            -Target (Join-Path $TreeWin "submod\.git") | Out-Null
    }
    MakeFixture
    $inodes = Vm "stat -c %i $Ptr/.git '$Ptr/GIT~1'"
    $inodeList = @($inodes -split "`n" | Where-Object { $_ -match '^\d+$' })
    Check "GIT~1 names the pointer file's inode in the machine: $($inodeList -join ' ')" `
        (($inodeList.Count -eq 2) -and ($inodeList[0] -eq $inodeList[1]))
    $clone = Outside "git -c safe.directory='*' clone --quiet $RepoVm $Repo"
    if ($clone.Trim() -ne "") { Info "clone: $($clone -replace "`n", ' ')" }
    $fixturesPresent = (Test-Path (Join-Path $TreeWin ".git\config")) -and (Test-Path (Join-Path $PtrWin ".git")) -and
        (Test-Path (Join-Path $Fix "repo\.git"))
    Check "the fixtures and a clone of this repository exist on the share" $fixturesPresent
    $fixtureCheck = Outside "$Exercise check $Tree"
    Check "the fixture holds every operand the corpus needs: $(($fixtureCheck -split "`n")[-1])" `
        ((Field "gaps" $fixtureCheck) -eq "0")
    Remove-Item -Recurse -Force $TreeWin, $PtrWin
    MakeFixture
    $deepest = (Outside ("cd $Repo && git ls-files | awk -F/ 'NF > max { max = NF; deepest = `$0 " +
        "} END { print deepest }'")).Trim()
    $deepestDepth = ($deepest -split "/").Count
    # The rule files, as phase3.sh writes them.
    $defaultsPath = Join-Path $RepoDir "src\main\resources\agentsandbox\file-rule-defaults"
    $defaults = @(Get-Content $defaultsPath |
        ForEach-Object { ($_ -replace "#.*", "").Trim() } | Where-Object { ($_ -split "\s+").Count -eq 2 })
    Info "defaults: $($defaults.Count) lines read from $defaultsPath"
    $rulesA = @($defaults) + @("writable .vscode/settings.json")
    $i = $rulesA.Count
    while ($i -lt 124) { $rulesA += "read-only zz-filler-$i"; $i++ }
    $rulesB = @($rulesA) + @("read-only README.md")
    $rulesA += "read-only zz-filler-last"
    # An anchored line stands first, ahead of every floating line, as in phase3.sh.
    $first = @("read-only githooks anchored")
    $anchored = @("pinned-path shared anchored", "pinned-path shared/claude anchored alias=.claude")
    [IO.File]::WriteAllText((Join-Path $Fix "rules-a.txt"), (($first + $rulesA + $anchored) -join "`n") + "`n")
    [IO.File]::WriteAllText((Join-Path $Fix "rules-b.txt"), (($first + $rulesB + $anchored) -join "`n") + "`n")
    $RulesA = "$FixVm/rules-a.txt"
    $RulesB = "$FixVm/rules-b.txt"
    $linesA = @(Get-Content (Join-Path $Fix "rules-a.txt")).Count
    $linesB = @(Get-Content (Join-Path $Fix "rules-b.txt")).Count
    Info "rule lines: $linesA in A, $linesB in B"
    $RootsA = "--root workspace=$Tree --root workspace=$Ptr --root workspace=$Repo " +
        "--root gitdir=$Tree/.git/modules/sub --root guarded-git=$Ptr/.git --root guarded-git=$Tree/submod/.git " +
        "--root guarded-git=$Tree/.git --root guarded-git=$Repo/.git " +
        "--root guarded-sandbox=$Ptr/.ko-agent-sandbox --root guarded-sandbox=$Tree/.ko-agent-sandbox " +
        "--root volume=$VolMp --vol-fs-type $VolFs"
    $Pin = "$PinRoot/a/file_open"
    function AttachA([string]$flags, [string]$hooks) {
        $flagOpt = if ($flags -eq "-") { "" } else { "--flags $flags" }
        Vm "sudo -n $Ctl unpin $PinRoot/a" | Out-Null
        $out = Vm ("sudo -n $Ctl attach policy.bpf.o $($CG[1]) $PinRoot/a --fs-type $FsType --rules " +
            "$RulesA $flagOpt $RootsA $hooks")
        foreach ($line in ($out -split "`n" | Where-Object { $_ -match '^(root|alias|policy|attached) ' })) {
            Log "  $line"
        }
        $out
    }
    $attach = AttachA "-" $Hooks8
    Check "the live session's policy attached with 128 rules, one alias and eleven roots" `
        (((Field "count" $attach) -eq "8") -and ((Field "rule_count" $attach) -eq "128"))
    $aliasLine = Lines $attach '^alias '
    Check "the alias context of .claude holds the five .claude lines as partial matches" `
        (($aliasLine -replace '[^,]', '').Length -ge 5)

    # -----------------------------------------------------------------------
    Step "the corpus, git in the clone, the race, the storm, sockets, a second share"
    # -----------------------------------------------------------------------
    $corpus = InCg 1 "$Exercise corpus $Tree"
    foreach ($line in ($corpus -split "`n" | Where-Object { $_ -match 'MISMATCH|UNSUPPORTED' })) { Log "  $line" }
    Check "the corpus: $(Lines $corpus '^corpus ')" ((Field "mismatches" $corpus) -eq "0")
    Info (Vm "sudo -n $Ctl last-decision $Pin")
    $gitOk = InCg 1 ("cd $Repo && git status --short > /dev/null && git add -A && git -c user.name=probe " +
        "-c user.email=probe@example.invalid commit -q --allow-empty -m probe && git checkout -q " +
        "-b probe && git log -1 --oneline > /dev/null && git gc -q && echo GIT_OK")
    Check "ordinary git in the clone: status, add, commit, branch, log, gc" (Has "GIT_OK" $gitOk)
    $gitConfig = InCg 1 ("cd $Repo && (git config probe.key value 2>&1 || echo CONFIG_REFUSED) && " +
        "(git init -q sub2 2>&1 || echo INIT_REFUSED)")
    Check "git config and git init in the clone are refused" `
        ((Has "CONFIG_REFUSED" $gitConfig) -and (Has "INIT_REFUSED" $gitConfig))
    $hostGit = Outside "cd $Tree/sub && git rev-parse --absolute-git-dir 2>&1"
    Check "git outside the policy in sub/, whose .git has no HEAD, finds the workspace's gitdir: $hostGit" `
        (Has "$Tree/.git" $hostGit)
    Vm "sudo -n $Ctl reset-stats $Pin" | Out-Null
    $race = InCg 1 "$Exercise race $Tree $RaceSeconds"
    $stats = Vm "sudo -n $Ctl stats $Pin"
    foreach ($line in ($stats -split "`n")) { Log "  $line" }
    Check "the race: $((Lines $race '^race ') -replace "`n", ' ')" `
        (((Field "succeeded" $race) -eq "0") -and ((SumField "gave_up" $stats) -eq 0))
    # The race ran when both renamers moved and the writer met both names, refused under one and
    # absent under the other; the torn reads the walk caught, its retries, are information (phase3.sh).
    $renames = $race -split "`n" | Where-Object { $_ -match '^race renamer=' } |
        ForEach-Object { [int](Field "renames" $_) }
    Check "the race ran: both renamers moved, and the writer saw refusals and absences" `
        ((($renames | Measure-Object -Minimum).Minimum -gt 0) -and ([int](Field "refused" $race) -gt 0) -and
            ([int](Field "absent" $race) -gt 0))
    Info "walks that read a torn name and were made again: $(SumField 'retries' $stats)"
    Vm "sudo -n $Ctl reset-stats $Pin" | Out-Null
    $storm = InCg 1 "$Exercise storm $Tree $StormProcs $StormSeconds"
    $stats = Vm "sudo -n $Ctl stats $Pin"
    foreach ($line in ($stats -split "`n")) { Log "  $line" }
    foreach ($line in ($storm -split "`n" | Where-Object { $_ -match '^storm process' })) { Log "  $line" }
    Check "the storm: $(Lines $storm '^storm processes')" ((Field "failed" $storm) -eq "0")
    $nestedMax = ($stats -split "`n" | ForEach-Object { if ($_ -match 'nested_max=(\d+)') { [int]$Matches[1] } } |
        Measure-Object -Maximum).Maximum
    Info ("reentry: $(SumField 'reentry' $stats) calls denied for want of a slot; the deepest nesting " +
        "on one CPU: slot $nestedMax")
    function SlotWrite([string]$mask, [string]$name) {
        & podman rm -f ko-agent-bpf3-slot 2>&1 | Out-Null
        & podman run -d --name ko-agent-bpf3-slot "--cgroup-parent=$($PARENT[1])" @ExerciserOpts $ProbeImage sh -c `
            "sleep 3; (echo x > $Tree/apps/$name) 2>&1 && echo SLOT_OK || echo SLOT_REFUSED" 2>&1 | Out-Null
        Start-Sleep -Seconds 1
        Vm "sudo -n $Ctl reset-stats $Pin; sudo -n $Ctl guard $Pin $mask" | Out-Null
        & podman wait ko-agent-bpf3-slot 2>&1 | Out-Null
        Vm "sudo -n $Ctl guard $Pin 0" | Out-Null
        $out = (& podman logs ko-agent-bpf3-slot 2>&1 | ForEach-Object { "$_" }) -join "`n"
        Add-Content -Path $Transcript -Value $out -Encoding UTF8
        & podman rm -f ko-agent-bpf3-slot 2>&1 | Out-Null
        $out
    }
    function CreateNested([string]$stats) {
        [regex]::Match((Lines $stats 'hook=inode_create'), 'nested_max=(\d+)').Groups[1].Value
    }
    $full = SlotWrite "0xf" "slot-full"
    $stats = Vm "sudo -n $Ctl stats $Pin"
    Check "with every slot taken a write on the share is refused and counted as reentry: $(SumField 'reentry' $stats)" `
        ((Has "SLOT_REFUSED" $full) -and ((SumField "reentry" $stats) -gt 0))
    $three = SlotWrite "0x7" "slot-three"
    $stats = Vm "sudo -n $Ctl stats $Pin"
    Check "with three slots taken a write runs in the fourth: nested_max 3, no reentry" `
        ((Has "SLOT_OK" $three) -and ((CreateNested $stats) -eq "3"))
    $freed = SlotWrite "0" "slot-freed"
    $stats = Vm "sudo -n $Ctl stats $Pin"
    Check "with the slots freed a write runs in the first again" `
        ((Has "SLOT_OK" $freed) -and ((CreateNested $stats) -eq "0"))
    $sockets = InCg 1 ("$Exercise bind /vol/s; $Exercise bind /home2/s; " +
        "(mv /home2/s /vol/s 2>&1 && echo MV_VOL_OK || echo MV_VOL_REFUSED); " +
        "(ln /home2/s /vol/s 2>&1 && echo LN_VOL_OK || echo LN_VOL_REFUSED); " +
        "(mv /home2/s $Tree/apps/s 2>&1 && echo MV_WS_OK || echo MV_WS_REFUSED)")
    $bindVol = (Lines $sockets '^bind path=/vol/s ')
    $bindHome = (Lines $sockets '^bind path=/home2/s ')
    Check "a socket is refused beneath the volume and allowed under /home2" `
        ((Field "result" $bindVol) -eq "EPERM" -and (Field "result" $bindHome) -eq "ok")
    Check "a socket bound under /home2 cannot be renamed or linked beneath the volume, nor moved into the workspace" `
        ((Has "MV_VOL_REFUSED" $sockets) -and (Has "LN_VOL_REFUSED" $sockets) -and (Has "MV_WS_REFUSED" $sockets))
    # The second share: the D: drive, when the machine serves it as a share of its own.
    if (Test-Path "D:\") {
        $script:Share2Win = "D:\ko-agent-bpf-phase3.$PID"
        New-Item -ItemType Directory -Force -Path $script:Share2Win | Out-Null
        $Share2 = MachinePath $script:Share2Win
        $share2Type = (Vm "findmnt -T $Share2 -n -o FSTYPE").Trim()
        $share2Target = (Vm "findmnt -T $Share2 -n -o TARGET").Trim()
        if (($share2Type -eq $FsType) -and ($share2Target -ne (Vm "findmnt -T $FixVm -n -o TARGET").Trim())) {
            $share2Script = "(echo x > /share2/f) 2>&1 && echo W_OK || echo W_REFUSED; " +
                "(mkdir /share2/d) 2>&1 && echo MKDIR_OK || echo MKDIR_REFUSED"
            $share2 = (& podman run --rm "--cgroup-parent=$($PARENT[1])" --userns=keep-id `
                --security-opt seccomp=unconfined --volume "${script:Share2Win}:/share2" $ProbeImage `
                sh -c $share2Script 2>&1 | ForEach-Object { "$_" }) -join "`n"
            Add-Content -Path $Transcript -Value $share2 -Encoding UTF8
            Check "a write on a second share of the same type, bound into the container, is refused: $share2" `
                (Has "W_REFUSED" $share2)
        } else {
            Info "second share: $Share2 is on $share2Type at $share2Target; not measured"
        }
    } else {
        Info "second share: no D: drive; not measured"
    }
    # The walk's cost: WalkPairs pairs of a container under the policy and one outside it, the policy's first in
    # the odd pairs so that the order is not confounded with the policy, each timing WalkCount opens for writing,
    # opens for reading, which the hook leaves before any walk, and lstats, which no hook sees.
    # The share's speed can drift within a pair by more than the walk costs ("Phase 3 on macOS"), so the figure that
    # resolves the walk is the program's own timer: file_open's mean over the pairs' write opens, read after them.
    Vm "sudo -n $Ctl reset-stats $Pin" | Out-Null
    $pairs = @()
    for ($n = 1; $n -le $WalkPairs; $n++) {
        if ($n % 2 -eq 1) {
            $first = "policy"
            $walk = InCg 1 "$Exercise walk-cost $Repo/$deepest $WalkCount"
            $bare = Outside "$Exercise walk-cost $Repo/$deepest $WalkCount"
        } else {
            $first = "bare"
            $bare = Outside "$Exercise walk-cost $Repo/$deepest $WalkCount"
            $walk = InCg 1 "$Exercise walk-cost $Repo/$deepest $WalkCount"
        }
        $pair = @{ n = $n; first = $first; failed = [int](Field "failed" $walk) + [int](Field "failed" $bare)
            policy_rdwr = [long](Field "open_rdwr_ns" $walk); bare_rdwr = [long](Field "open_rdwr_ns" $bare) }
        foreach ($key in "open_rdwr_ns", "open_rdonly_ns", "lstat_ns") {
            $pair[$key] = [long](Field $key $walk) - [long](Field $key $bare)
        }
        Log ("walk-pair n=$n first=$first rdwr=$($pair.open_rdwr_ns) rdonly=$($pair.open_rdonly_ns) " +
            "lstat=$($pair.lstat_ns) " +
            "policy_rdwr=$($pair.policy_rdwr) bare_rdwr=$($pair.bare_rdwr) failed=$($pair.failed)")
        $pairs += $pair
    }
    function Median([string]$key) {
        @($pairs | ForEach-Object { $_[$key] } | Sort-Object)[[math]::Floor(($pairs.Count - 1) / 2)]
    }
    $bareRdwr = $pairs | ForEach-Object { $_.bare_rdwr } | Measure-Object -Minimum -Maximum
    $failedOpens = ($pairs | ForEach-Object { $_.failed } | Measure-Object -Sum).Sum
    Info ("walk cost at the clone's deepest file, depth ${deepestDepth}, policy minus bare over $WalkPairs pairs, " +
        "the medians: open_rdwr=$(Median 'open_rdwr_ns') open_rdonly=$(Median 'open_rdonly_ns') " +
        "lstat=$(Median 'lstat_ns') ns; bare open_rdwr $($bareRdwr.Minimum) to $($bareRdwr.Maximum) ns; " +
        "failed=$failedOpens")
    Info ("in program over the pairs: " + ((Vm "sudo -n $Ctl stats $Pin") -split "`n" |
        Where-Object { $_ -match "^stats hook=file_open " } | Select-Object -First 1))
    $jited = Vm "sudo -n $Ctl jited $Pin /tmp/file_open.jited"
    Info $jited
    $fetchAdd = Field "fetch_add_insns" $jited
    $barrier = ($fetchAdd -ne "") -and ($fetchAdd -ne "0") -and
        (((Field "ldaddal" $jited) -ne "0") -or ((Field "dmb_ish" $jited) -ne "0") -or
            ((Field "lock_xadd" $jited) -ne "0"))
    Check "the xlated program holds the atomic fetch-add and the jited one a barrier instruction" $barrier

    # -----------------------------------------------------------------------
    Step "the NTFS short-name form, under its flag, and the generated short name of .vscode"
    # -----------------------------------------------------------------------
    $attach = AttachA "short-names" $Hooks8
    Check "the policy attached again with the short-names flag" `
        (((Field "count" $attach) -eq "8") -and ((Field "flags" $attach) -eq "1"))
    $corpus = InCg 1 "$Exercise corpus $Tree short"
    foreach ($line in ($corpus -split "`n" | Where-Object { $_ -match 'MISMATCH|UNSUPPORTED' })) { Log "  $line" }
    Check "the short-name corpus: $(Lines $corpus '^corpus ')" ((Field "mismatches" $corpus) -eq "0")
    # The generated short name of `.vscode` on the real volume, as `dir /x` lists it.
    $dirx = & cmd /c "dir /x `"$TreeWin`"" 2>&1 | ForEach-Object { "$_" }
    $shortLine = $dirx | Where-Object { $_ -match '\s(\S+~\d\S*)\s+\.vscode\s*$' }
    if ($shortLine) {
        $shortName = [regex]::Match($shortLine, '\s(\S+~\d\S*)\s+\.vscode\s*$').Groups[1].Value
        Info "NTFS serves .vscode as $shortName"
        $through = InCg 1 "(echo x > $Tree/$shortName/new.json) 2>&1 && echo SHORT_OK || echo SHORT_REFUSED"
        Check "a write through the generated short name of .vscode is refused under the flag: $through" `
            (Has "SHORT_REFUSED" $through)
        Check "the host saw no file arrive in .vscode through its short name" `
            (-not (Test-Path (Join-Path $TreeWin ".vscode\new.json")))
    } else {
        Info ("NTFS generates no short name for .vscode on this volume (8dot3name disabled); the " +
            "form row is the corpus's")
    }

    # -----------------------------------------------------------------------
    Step "--unix-sockets: four sandboxes, the socket corpus and descriptors between them"
    # -----------------------------------------------------------------------
    $attach = AttachA "unix-sockets" $Hooks9
    Check "A attached with nine hooks under unix-sockets" `
        (((Field "count" $attach) -eq "9") -and ((Field "flags" $attach) -eq "2"))
    $started = InCg 1 "echo STARTED"
    Check "a container starts under A with file_receive attached" (Has "STARTED" $started)
    Info (Vm "sudo -n $Ctl last-decision $PinRoot/a/file_receive")
    Info (Lines (Vm "sudo -n $Ctl stats $PinRoot/a/file_receive") 'hook=file_receive')
    $fds = InCg 1 "$Exercise fds"
    Check "the container's first process holds no descriptor of the runtime's: $(($fds -split "`n")[-1])" `
        ((Field "beyond_standard" $fds) -eq "0")
    $attach = Vm ("sudo -n $Ctl attach policy.bpf.o $($CG[2]) $PinRoot/b --fs-type $FsType --rules " +
        "$RulesB --flags unix-sockets $RootsA $Hooks9")
    Check "B attached with nine hooks and the later rule file" `
        (((Field "count" $attach) -eq "9") -and ((Field "rule_count" $attach) -eq "128"))
    $attach = Vm ("sudo -n $Ctl attach policy.bpf.o $($CG[3]) $PinRoot/c --fs-type $FsType --rules " +
        "$RulesA --flags unix-sockets --root workspace=$Repo --root volume=$VolMp --vol-fs-type $VolFs $Hooks9")
    Check "C, another workspace's session, attached" ((Field "count" $attach) -eq "9")
    $attach = Vm "sudo -n $Ctl attach policy.bpf.o $($CG[4]) $PinRoot/d --fs-type $FsType --flags unix-sockets $Hooks9"
    Check "D, a read-only session's policy with no root, attached" ((Field "count" $attach) -eq "9")
    $query = Vm "sudo -n $Ctl query $($CG[1])"
    Info (Lines $query '^slots ')
    Check "four sandboxes hold nine hooks of the ten slots" ((Field "hooks_in_use" $query) -eq "9")
    $corpus = InCg 1 "$Exercise corpus $Tree unix"
    foreach ($line in ($corpus -split "`n" | Where-Object { $_ -match 'MISMATCH|UNSUPPORTED' })) { Log "  $line" }
    Check "the socket corpus under unix-sockets: $(Lines $corpus '^corpus ')" ((Field "mismatches" $corpus) -eq "0")
    $readme = InCg 1 "(echo x >> $Tree/README.md) 2>&1 && echo A_OK || echo A_REFUSED"
    $readmeB = InCg 2 "(echo x >> $Tree/README.md) 2>&1 && echo B_OK || echo B_REFUSED"
    Check "A writes README.md and B, under the later rule file, cannot" `
        ((Has "A_OK" $readme) -and (Has "B_REFUSED" $readmeB))
    $ro = InCg 4 ("(echo x > $Tree/apps/ro) 2>&1 && echo WS_OK || echo WS_REFUSED; (echo x > /tmp/ro) " +
        "&& echo TMP_OK; cat $Tree/README.md > /dev/null && echo READ_OK")
    Check "D cannot write on the share, writes /tmp and reads the workspace" `
        ((Has "WS_REFUSED" $ro) -and (Has "TMP_OK" $ro) -and (Has "READ_OK" $ro))
    function PassFds([int]$sender, [int]$receiver, [string]$sock, [string[]]$specs, [string[]]$actions) {
        & podman rm -f ko-agent-bpf3-srv 2>&1 | Out-Null
        & podman run -d --name ko-agent-bpf3-srv "--cgroup-parent=$($PARENT[$sender])" @ExerciserOpts $ProbeImage `
            $Exercise serve $sock @specs 2>&1 | Out-Null
        $i = 0
        while ($i -lt 50 -and -not (((& podman logs ko-agent-bpf3-srv 2>&1) -join "`n").Contains("serve listening"))) {
            Start-Sleep -Milliseconds 200
            $i++
        }
        $script:Recv = InCg $receiver "$Exercise receive $sock $($actions -join ' ')"
        & podman wait ko-agent-bpf3-srv 2>&1 | Out-Null
        Add-Content -Path $Transcript -Value ((& podman logs ko-agent-bpf3-srv 2>&1) -join "`n") -Encoding UTF8
        & podman rm -f ko-agent-bpf3-srv 2>&1 | Out-Null
    }
    function Received([int]$count, [int]$ctrunc) {
        ((Field "received" $script:Recv) -eq "$count") -and ((Field "ctrunc" $script:Recv) -eq "$ctrunc")
    }
    $same = InCg 1 ("$Exercise serve /vol/s0 pipe pair ro:$Tree/README.md > /tmp/serve.log & sleep " +
        "1; $Exercise receive /vol/s0; wait; cat /tmp/serve.log")
    Check "a pipe, a socket pair's end and a workspace file pass between two processes of one container" `
        (((Field "received" $same) -eq "3") -and ((Field "ctrunc" $same) -eq "0"))
    PassFds 1 2 "/vol/s1" @("ro:$Tree/ordinary", "rw:$Tree/README.md", "ro:$Tree/ordinary") @()
    Check ("B gets the first of three descriptors from A and MSG_CTRUNC: the writable README.md is " +
        "refused by B's rules") `
        (Received 1 1)
    PassFds 1 2 "/vol/s2" @("rw:$Tree/ordinary", "ro:$Tree/README.md") @("write:0", "reopen:1")
    $writeResult = [regex]::Match($script:Recv, 'action=write:0 result=(\S+)').Groups[1].Value
    $reopenResult = [regex]::Match($script:Recv, 'action=reopen:1 result=(\S+)').Groups[1].Value
    Check "B gets a writable descriptor of a file its rules allow, and a read-only one, writes the first" `
        (((Field "received" $script:Recv) -eq "2") -and ($writeResult -eq "ok"))
    Check "B cannot reopen the read-only descriptor of README.md for writing" ($reopenResult -eq "EPERM")
    PassFds 1 2 "/vol/s3" @("dir:/", "dir:/tmp", "dir:$Tree") @()
    Check "B gets no directory descriptor from A: its container root, its /tmp, the receiver's own root" (Received 0 1)
    PassFds 1 3 "/vol/s4" @("ro:$Tree/ordinary", "ro:$Tree/ordinary") @()
    Check "C, another workspace's session, gets no descriptor of this workspace" (Received 0 1)
    PassFds 1 4 "/vol/s5" @("ro:$Tree/ordinary", "rw:$Tree/ordinary") @()
    Check "D, the read-only session, gets no descriptor of the share" (Received 0 1)
    PassFds 2 1 "/vol/s6" @("dir:/", "pipe") @()
    Check "A gets no directory descriptor from B, and the pipe after it is dropped with it" (Received 0 1)
    PassFds 2 1 "/vol/s7" @("pipe", "dir:/tmp") @()
    Check "A gets the pipe before a refused directory descriptor from B" (Received 1 1)
    function PassFdsAfterExit([string]$sock, [string[]]$specs) {
        & podman rm -f ko-agent-bpf3-srv ko-agent-bpf3-rcv 2>&1 | Out-Null
        & podman run -d --name ko-agent-bpf3-srv "--cgroup-parent=$($PARENT[1])" @ExerciserOpts $ProbeImage `
            $Exercise serve $sock then-exit @specs 2>&1 | Out-Null
        $i = 0
        while ($i -lt 50 -and -not (((& podman logs ko-agent-bpf3-srv 2>&1) -join "`n").Contains("serve listening"))) {
            Start-Sleep -Milliseconds 200
            $i++
        }
        & podman run -d --name ko-agent-bpf3-rcv "--cgroup-parent=$($PARENT[2])" @ExerciserOpts $ProbeImage `
            $Exercise receive $sock "wait-for:$sock.gone" 2>&1 | Out-Null
        & podman wait ko-agent-bpf3-srv 2>&1 | Out-Null
        Add-Content -Path $Transcript -Value ((& podman logs ko-agent-bpf3-srv 2>&1) -join "`n") -Encoding UTF8
        & podman rm -f ko-agent-bpf3-srv 2>&1 | Out-Null
        Vm "touch $VolMp/$(Split-Path $sock -Leaf).gone" | Out-Null
        & podman wait ko-agent-bpf3-rcv 2>&1 | Out-Null
        $script:Recv = (& podman logs ko-agent-bpf3-rcv 2>&1 | ForEach-Object { "$_" }) -join "`n"
        Add-Content -Path $Transcript -Value $script:Recv -Encoding UTF8
        & podman rm -f ko-agent-bpf3-rcv 2>&1 | Out-Null
    }
    PassFdsAfterExit "/vol/s8" @("rw:$Tree/README.md", "dir:$Tree", "ro:$Tree/ordinary")
    $last = Vm "sudo -n $Ctl last-decision $PinRoot/b/file_receive"
    Info $last
    Check "B, receiving after A's container ended, gets neither the writable README.md nor the directory" `
        (Received 0 1)
    Check "the refused descriptor's mount was in no namespace: the sender's was torn down before the read" `
        (((Field "ns_inum" $last) -eq "0") -and ((Field "name" $last) -eq "README.md"))
    PassFdsAfterExit "/vol/s9" @("ro:$Tree/ordinary")
    Check "B, receiving after A's container ended, gets a read-only share file its policy allows" (Received 1 0)
    Info (Lines (Vm "sudo -n $Ctl stats $PinRoot/b/file_receive") 'hook=file_receive')
    foreach ($pin in @("a", "b", "c", "d")) { Vm "sudo -n $Ctl unpin $PinRoot/$pin" | Out-Null }

    # -----------------------------------------------------------------------
    Step "the namespaces and mounts a generated seccomp profile refuses"
    # -----------------------------------------------------------------------
    # The profile is derived in the machine by its python3, as phase3.sh derives it on the host:
    # PowerShell 5.1's JSON reader rejected the machine's default profile once.
    $generator = @'
import json, sys
profile = json.load(open(sys.argv[1]))
mounts = ["mount", "fsopen", "fsconfig", "fsmount", "fspick", "move_mount", "open_tree", "open_tree_attr",
          "mount_setattr", "umount2", "umount", "pivot_root"]
family = set(mounts) | {"clone", "clone3", "unshare"}
for entry in profile["syscalls"]:
    entry["names"] = [name for name in entry["names"] if name not in family]
profile["syscalls"] = [entry for entry in profile["syscalls"] if entry["names"]]
CLONE_NEWUSER = 0x10000000
rules = [{"names": ["clone3"], "action": "SCMP_ACT_ERRNO", "errnoRet": 38},
         {"names": mounts, "action": "SCMP_ACT_ERRNO", "errnoRet": 1}]
for name in ("clone", "unshare"):
    rules.append({"names": [name], "action": "SCMP_ACT_ERRNO", "errnoRet": 1,
        "args": [{"index": 0, "value": CLONE_NEWUSER, "valueTwo": CLONE_NEWUSER, "op": "SCMP_CMP_MASKED_EQ"}]})
    rules.append({"names": [name], "action": "SCMP_ACT_ALLOW",
        "args": [{"index": 0, "value": CLONE_NEWUSER, "valueTwo": 0, "op": "SCMP_CMP_MASKED_EQ"}]})
profile["syscalls"] = rules + profile["syscalls"]
json.dump(profile, open(sys.argv[2], "w"))
'@
    $generatorVm = ScriptFile "seccomp-gen.py" $generator
    Vm "python3 $generatorVm /usr/share/containers/seccomp.json $FixVm/seccomp.json" | Out-Null
    $ns = (& podman run --rm "--cgroup-parent=$($PARENT[1])" --userns=keep-id `
        --security-opt "seccomp=$(Join-Path $Fix 'seccomp.json')" --volume "${Fix}:${FixVm}" $ProbeImage `
        sh -c "$Exercise namespaces; echo CHILD_RAN" 2>&1 | ForEach-Object { "$_" }) -join "`n"
    Add-Content -Path $Transcript -Value $ns -Encoding UTF8
    $refused = $true
    $calls = @("unshare_newuser", "unshare_newns", "mount", "fsopen", "open_tree", "move_mount", "fsmount", "fspick",
        "mount_setattr", "umount2", "pivot_root")
    foreach ($call in $calls) {
        if ([regex]::Match($ns, "namespaces $call=(\S+)").Groups[1].Value -ne "EPERM") { $refused = $false }
    }
    Check "under the generated profile a user namespace and every mount syscall answer EPERM, and a child still runs" `
        ($refused -and (Has "CHILD_RAN" $ns))
} finally {
    Cleanup
}
if ($script:failed -ne 0) { exit 1 }
