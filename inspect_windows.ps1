$ErrorActionPreference = 'Stop'
$ports = @(80,443,8443,8767,24443,3389)
$listeners = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
    Where-Object { $_.LocalPort -in $ports } | ForEach-Object {
        $p = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
        [PSCustomObject]@{
            Port = $_.LocalPort
            Address = $_.LocalAddress
            Process = $p.ProcessName
            Executable = $p.Path
        }
    })
$candidates = @('C:\ProgramData\Trojan','C:\ProgramData\trojan-go',
                'C:\Trojan','C:\trojan-go','C:\ProgramData\Caddy','C:\ProgramData\win-acme')
$certificates = @($candidates | Where-Object { Test-Path $_ } | ForEach-Object {
    Get-ChildItem -LiteralPath $_ -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Extension -in @('.pem','.crt','.cer','.key') } |
        Select-Object -First 20 -ExpandProperty FullName
})
$os = Get-CimInstance Win32_OperatingSystem
$python = Get-Command python.exe -ErrorAction SilentlyContinue
$git = Get-Command git.exe -ErrorAction SilentlyContinue
$gitSystem = Join-Path $env:ProgramFiles 'Git\cmd\git.exe'
[PSCustomObject]@{
    OS = $os.Caption
    Build = $os.BuildNumber
    MemoryGB = [math]::Round($os.TotalVisibleMemorySize / 1MB, 2)
    Python = $python.Source
    Git = $git.Source
    GitSystemInstall = (Test-Path $gitSystem)
    Listeners = $listeners
    CertificateFilePathsOnly = $certificates
} | ConvertTo-Json -Depth 5
