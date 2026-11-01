# plain-bind.sh for a Windows host; plain-bind.sh says what this control run is. Run it in
# PowerShell, in the scratch workspace the benchmark or probe was copied to:
#
#     ...\bench\plain-bind.ps1 python3 entry-cost.py
#
# The target is the path where a session has the workspace root (SandboxWorkspace.mountPathOf):
# the path at which the podman machine serves the drive.
if ($args.Count -eq 0) { Write-Error "usage: plain-bind.ps1 <command> [args...]"; exit 2 }

$workspace = (Get-Location).Path
$target = "/mnt/" + $workspace.Substring(0, 1).ToLower() + "/" + $workspace.Substring(3).Replace("\", "/")
podman run --rm -i --network=none --entrypoint= `
    --userns=keep-id:uid=65532,gid=65532 --user=65532:65532 `
    "--volume=${workspace}:${target}:rw" "--workdir=$target" `
    ko-agent-sandbox:latest @args
exit $LASTEXITCODE
