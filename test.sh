#!/bin/bash

# Girdi dosyası (domain listesi)
INPUT_FILE="domain.txt"

# Çıktıların kaydedileceği klasör (isteğe bağlı, otomatik oluşturulur)
OUTPUT_DIR="whois_results"
mkdir -p "$OUTPUT_DIR"

# Renkli çıktı için (opsiyonel)
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Dosya kontrolü
if [[ ! -f "$INPUT_FILE" ]]; then
    echo -e "${RED}Hata: $INPUT_FILE dosyası bulunamadı!${NC}"
    exit 1
fi

echo -e "${GREEN}==> $INPUT_FILE içindeki domain/IP'ler işleniyor...${NC}"

# Her satırı oku (boş satırları ve yorum satırlarını atla)
while IFS= read -r target; do
    # Boşlukları temizle
    target=$(echo "$target" | xargs)
    
    # Boş veya yorum satırıysa geç
    [[ -z "$target" || "$target" =~ ^# ]] && continue
    
    echo -e "${GREEN}İşleniyor: $target${NC}"
    
    # Çıktı dosyası adı (geçersiz karakterleri _ ile değiştir)
    safe_name=$(echo "$target" | sed 's/[^a-zA-Z0-9.-]/_/g')
    output_file="$OUTPUT_DIR/${safe_name}_whois.txt"
    
    # Whois sorgusu (pasif)
    echo "========== WHOIS ($target) ==========" > "$output_file"
    whois "$target" >> "$output_file" 2>&1
    
    # Dig ile DNS kayıtları (pasif)
    echo -e "\n========== DIG (A, AAAA, MX, NS, TXT) ==========" >> "$output_file"
    dig "$target" A +short >> "$output_file" 2>&1
    dig "$target" AAAA +short >> "$output_file" 2>&1
    dig "$target" MX +short >> "$output_file" 2>&1
    dig "$target" NS +short >> "$output_file" 2>&1
    dig "$target" TXT +short >> "$output_file" 2>&1
    
    # İsteğe bağlı: nslookup veya host komutu da eklenebilir
    echo -e "\n========== NSLOOKUP ==========" >> "$output_file"
    nslookup "$target" >> "$output_file" 2>&1
    
    echo -e "${GREEN}   Sonuçlar kaydedildi: $output_file${NC}"
    
    # Her domain arasında küçük bir bekleme (rate limit aşmamak için)
    sleep 1
done < "$INPUT_FILE"

echo -e "${GREEN}\n✅ Tüm işlemler tamamlandı. Sonuçlar '$OUTPUT_DIR' klasöründe.${NC}"
