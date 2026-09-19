# unfiltered.sh for a Windows host: see it for what this control is. Run it in PowerShell, in the
# scratch project the probe was copied to:
#
#     ...\probe\unfiltered.ps1 python3 perf-probe.py
#
# The target is where a session has the project (SandboxProject.mountPathOf): the path the
# podman machine serves the drive at.
if ($args.Count -eq 0) { Write-Error "usage: unfiltered.ps1 <command> [args...]"; exit 2 }

$project = (Get-Location).Path
$target = "/mnt/" + $project.Substring(0, 1).ToLower() + "/" + $project.Substring(3).Replace("\", "/")
podman run --rm -i --network=none --entrypoint= `
    --userns=keep-id:uid=65532,gid=65532 --user=65532:65532 `
    "--volume=${project}:${target}:rw" "--workdir=$target" `
    ko-agent-sandbox:latest @args
exit $LASTEXITCODE
