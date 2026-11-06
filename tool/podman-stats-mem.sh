# MemPerc: MemUsage (used / limit) × 100%
# CPUPerc: 100% = 1 fully utilized vCPU
podman stats --format 'table {{.Name}}\t{{.MemUsage}}\t{{.MemPerc}}\t{{.CPUPerc}}'
