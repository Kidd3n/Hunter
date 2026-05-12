#!/bin/bash

# ============================================================
#  Hunter v3 - Bug Bounty Recon & Vulnerability Scanner
#  Github: https://github.com/Kidd3n
#  Discord: kidd3n.sh
# ============================================================

# Colors
greenColour="\e[0;32m\033[1m"
endColour="\033[0m\e[0m"
redColour="\e[0;31m\033[1m"
blueColour="\e[0;34m\033[1m"
yellowColour="\e[0;33m\033[1m"
purpleColour="\e[0;35m\033[1m"
turquoiseColour="\e[0;36m\033[1m"
grayColour="\e[0;37m\033[1m"

# ─── Helpers ──────────────────────────────────────────────

banner() {
    echo -ne "${redColour}"
    echo -ne "                    _            \n"
    echo -ne "  /\\  /\\_   _ _ __ | |_ ___ _ __ \n"
    echo -ne " / /_/ / | | | '_ \\| __/ _ \\ '__|\n"
    echo -ne "/ __  /| |_| | | | | ||  __/ |   \n"
    echo -ne "\\/ /_/  \\__,_|_| |_|\\__\\___|_|   \n"
    echo -e "${grayColour}                           v3${endColour}\n"
}

info()    { echo -e "${blueColour}[*]${endColour}${grayColour} $1${endColour}"; }
success() { echo -e "${greenColour}[+]${endColour}${grayColour} $1${endColour}"; }
warn()    { echo -e "${yellowColour}[!]${endColour}${grayColour} $1${endColour}"; }
error()   { echo -e "${redColour}[-]${endColour}${grayColour} $1${endColour}"; }
ask()     { echo -ne "${purpleColour}[?]${endColour}${grayColour} $1${endColour}"; }
section() { echo -e "\n${yellowColour}════════════════════════════════════════${endColour}"; echo -e "${turquoiseColour}  $1${endColour}"; echo -e "${yellowColour}════════════════════════════════════════${endColour}"; }

trap ctrl_c INT
ctrl_c() {
    echo -e "\n\n${redColour}[!]${endColour}${grayColour} Interrupted. Exiting...${endColour}\n"
    tput cnorm; exit 1
}

pause() { echo -ne "\n${blueColour}[+]${grayColour} Press Enter to continue${endColour}" && read; }

validate_file() {
    local file="$1"
    while [[ ! -f "$file" || ! -s "$file" ]]; do
        error "File '$file' not found or empty."
        ask "Enter a valid file path: "; read file
    done
    echo "$file"
}

normalize_url() {
    local input="$1"
    [[ ! "$input" =~ ^https?:// ]] && echo "https://$input" || echo "$input"
}

clean_domain() {
    echo "$1" | sed -e 's|^[^/]*//||' -e 's|/.*$||' -e 's|:[0-9]*$||'
}

# ─── Dependency Installer ──────────────────────────────────

install_go_tool() {
    local name="$1" pkg="$2" bin="$3"
    info "Installing $name..."
    if go install "$pkg" 2>/dev/null; then
        sudo cp ~/go/bin/"$bin" /usr/local/bin/ 2>/dev/null
        success "$name installed."
    else
        error "Failed to install $name. Try manually: go install $pkg"
    fi
}

programs() {
    section "Checking Dependencies"
    sleep 0.2

    # Go
    if ! command -v go &>/dev/null; then
        info "Installing Go..."
        sudo apt install -y golang-go 2>/dev/null && success "Go installed." || error "Failed to install Go."
    else
        success "Go is already installed."
    fi

    # pip tools
    if ! command -v uro &>/dev/null; then
        info "Installing uro..."
        pipx install uro --force 2>/dev/null && sudo cp ~/.local/bin/uro /usr/local/bin/ 2>/dev/null
    else
        success "uro is already installed."
    fi

    # apt tools
    for apt_tool in httpx-toolkit python3-pip pipx wget git curl; do
        if ! command -v "$apt_tool" &>/dev/null; then
            info "Installing $apt_tool..."
            sudo apt install -y "$apt_tool" 2>/dev/null
        fi
    done

    # Go tools: name|package|binary
    declare -A go_tools=(
        [katana]="github.com/projectdiscovery/katana/cmd/katana@latest|katana"
        [Gxss]="github.com/KathanP19/Gxss@latest|Gxss"
        [kxss]="github.com/Emoe/kxss@latest|kxss"
        [gf]="github.com/tomnomnom/gf@latest|gf"
        [anew]="github.com/tomnomnom/anew@latest|anew"
        [httpx]="github.com/projectdiscovery/httpx/cmd/httpx@latest|httpx"
        [subfinder]="github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest|subfinder"
        [gau]="github.com/lc/gau/v2/cmd/gau@latest|gau"
        [qsreplace]="github.com/tomnomnom/qsreplace@latest|qsreplace"
        [interactsh-client]="github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest|interactsh-client"
        [dalfox]="github.com/hahwul/dalfox/v2@latest|dalfox"
        [waybackurls]="github.com/tomnomnom/waybackurls@latest|waybackurls"
        [hakrawler]="github.com/hakluke/hakrawler@latest|hakrawler"
    )

    for tool in "${!go_tools[@]}"; do
        if ! command -v "$tool" &>/dev/null; then
            IFS='|' read -r pkg bin <<< "${go_tools[$tool]}"
            install_go_tool "$tool" "$pkg" "$bin"
        else
            success "$tool is already installed."
        fi
    done

    # pipx tools — check command, ~/.local/bin and pipx venvs (handles sudo installs too)
    pipx_check() {
        local name="$1"
        command -v "$name" &>/dev/null ||         [[ -f "$HOME/.local/bin/$name" ]] ||         [[ -f "/root/.local/bin/$name" ]] ||         pipx list 2>/dev/null | grep -qi "$name"
    }

    if ! pipx_check waymore; then
        info "Installing waymore..."
        pip3 install waymore 2>/dev/null && success "waymore installed." || error "Failed to install waymore."
    else
        success "waymore is already installed."
    fi




    # gf patterns
    install_gf_patterns

    clear
}

install_gf_patterns() {
    if [[ -f ~/.gf/sqli.json ]]; then
        success "gf patterns already installed."
        return
    fi
    info "Installing gf patterns..."
    mkdir -p ~/.gf
    git clone https://github.com/coffinxp/GFpattren.git /tmp/GFpattren 2>/dev/null
    mv /tmp/GFpattren/*.json ~/.gf/ 2>/dev/null
    rm -rf /tmp/GFpattren 2>/dev/null

    # Extra patterns for SSRF, CORS, IDOR
    cat > ~/.gf/ssrf.json <<'EOF'
{"flags":"-iE","pattern":"(url|uri|path|dest|redirect|next|target|redir|return|returnTo|out|view|reference|site|html|open|file|http|https|feed|host|port|proxy|callback|goto)="}
EOF
    cat > ~/.gf/cors.json <<'EOF'
{"flags":"-iE","pattern":"(origin|access-control|cors)"}
EOF
    cat > ~/.gf/idor.json <<'EOF'
{"flags":"-iE","pattern":"(id|user_id|account|order|invoice|ticket|number|ref|doc|key|file|uid|pid|rid|bid|mid)=[0-9]+"}
EOF
    success "gf patterns installed."
}

# ─── URL Collection ────────────────────────────────────────

collect_urls() {
    local target="$1" outdir="$2"
    local url; url=$(normalize_url "$target")
    local domain; domain=$(clean_domain "$target")

    info "Collecting URLs from passive sources (katana)..."
    echo "$url" | katana -ps -pss waybackarchive,commoncrawl,alienvault -jc -f qurl -silent 2>/dev/null | uro >> "$outdir/all_urls.txt"

    info "Collecting URLs from Wayback Machine (waybackurls)..."
    echo "$domain" | waybackurls 2>/dev/null | uro | anew "$outdir/all_urls.txt" >/dev/null

    info "Collecting URLs from GAU..."
    echo "$domain" | gau --threads 5 --subs 2>/dev/null | uro | anew "$outdir/all_urls.txt" >/dev/null

    info "Collecting URLs from waymore..."
    waymore -i "$domain" -mode U 2>/dev/null | uro | anew "$outdir/all_urls.txt" >/dev/null

    info "Crawling actively with katana..."
    katana -u "$url" -d 5 -jc -f qurl -silent 2>/dev/null | uro | anew "$outdir/all_urls.txt" >/dev/null

    info "Crawling with hakrawler..."
    echo "$url" | hakrawler -d 3 -subs 2>/dev/null | anew "$outdir/all_urls.txt" >/dev/null

    [[ ! -s "$outdir/all_urls.txt" ]] && rm -f "$outdir/all_urls.txt"
    local count; count=$(wc -l < "$outdir/all_urls.txt" 2>/dev/null || echo 0)
    success "Total URLs collected: $count"
}

# ─── Vulnerability Filtering ───────────────────────────────

filter_vulns() {
    local urlfile="$1" outdir="$2"


    section "Filtering Vulnerability Vectors"

    # Helper: saves clean URLs with empty param values — only writes if data non-empty
    make_vuln_files() {
        local name="$1" raw_data="$2"
        [[ -z "$raw_data" ]] && return
        local cleaned; cleaned=$(echo "$raw_data" | sed 's/=[^&]*/=/g' | sort -u)
        [[ -z "$cleaned" ]] && return
        echo "$cleaned" | anew "$outdir/${name}.txt" >/dev/null
    }

    info "Filtering SQLi..."
    sqli_data=$(cat "$urlfile" | gf sqli)
    make_vuln_files "sqli" "$sqli_data"

    info "Filtering XSS (Gxss + kxss)..."
    xss_data=$(cat "$urlfile" | Gxss 2>/dev/null | kxss 2>/dev/null | grep -oP '^URL: \K\S+')
    make_vuln_files "xss" "$xss_data"

    info "Filtering LFI..."
    lfi_data=$(cat "$urlfile" | gf lfi)
    make_vuln_files "lfi" "$lfi_data"

    info "Filtering Open Redirect..."
    or_data=$(cat "$urlfile" | gf or)
    make_vuln_files "open_redirect" "$or_data"

    info "Filtering SSRF candidates..."
    ssrf_data=$(cat "$urlfile" | gf ssrf 2>/dev/null)
    make_vuln_files "ssrf" "$ssrf_data"

    info "Filtering IDOR candidates..."
    idor_data=$(cat "$urlfile" | gf idor 2>/dev/null)
    make_vuln_files "idor" "$idor_data"

    info "Filtering RCE/SSTI..."
    rce_data=$(cat "$urlfile" | gf rce 2>/dev/null)
    make_vuln_files "rce" "$rce_data"

    info "Filtering CORS configuration..."
    local cors_data; cors_data=$(cat "$urlfile" | gf cors 2>/dev/null | sort -u)
    [[ -n "$cors_data" ]] && echo "$cors_data" | anew "$outdir/cors.txt" >/dev/null

    info "Checking CORS misconfigurations..."
    local cors_found=0
    while read -r url; do
        [[ -z "$url" ]] && continue
        local domain_cors; domain_cors=$(clean_domain "$url")
        local response
        response=$(curl -sk -H "Origin: https://evil-${domain_cors}.com"             -H "Access-Control-Request-Method: GET"             --max-time 5 -I "$url" 2>/dev/null)
        local acao; acao=$(echo "$response" | grep -i "access-control-allow-origin" | head -1)
        local acac; acac=$(echo "$response" | grep -i "access-control-allow-credentials" | head -1)
        if echo "$acao" | grep -qiE "evil|null|\*"; then
            echo "[CORS VULN] $url | $acao | $acac" | anew "$outdir/cors_vulnerable.txt" >/dev/null
            ((cors_found++))
        fi
    done < <(head -200 "$urlfile")
    [[ $cors_found -gt 0 ]] && warn "$cors_found CORS misconfigurations found → $outdir/cors_vulnerable.txt"                              || success "No CORS misconfigurations found."

    info "Checking SSRF candidates count..."
    [[ -s "$outdir/ssrf.txt" ]] && warn "$(wc -l < "$outdir/ssrf.txt") SSRF candidate URLs — use interactsh payload to test."                                  || info "No SSRF candidates found."

    # Remove empty files
    find "$outdir" -maxdepth 1 -type f -name "*.txt" -empty -delete

    warn "Vulnerability filter complete."
}

# ─── JS Analysis ───────────────────────────────────────────

js_analysis() {
    local urlfile="$1" outdir="$2"
    local js_dir="$outdir/js_analysis"
    mkdir -p "$js_dir"

    section "JavaScript Analysis"

    info "Extracting JS files..."
    cat "$urlfile" | grep -iE "\.js(\?|$)" | sort -u | grep -v "^$" > /tmp/js_files_tmp.txt
    [[ -s /tmp/js_files_tmp.txt ]] && mv /tmp/js_files_tmp.txt "$js_dir/js_files.txt" || rm -f /tmp/js_files_tmp.txt

    local jscount=0
    [[ -f "$js_dir/js_files.txt" ]] && jscount=$(wc -l < "$js_dir/js_files.txt")
    info "Found $jscount JS files. Analyzing..."

    if [[ $jscount -eq 0 ]]; then
        warn "No JS files found to analyze."
        return
    fi

    # ── Fetch all JS content ──
    info "Fetching JS file contents..."
    local js_content_dir="$js_dir/content"
    mkdir -p "$js_content_dir"
    while read -r jsurl; do
        [[ -z "$jsurl" ]] && continue
        local fname; fname=$(echo "$jsurl" | md5sum | cut -d' ' -f1).js
        curl -sk --max-time 10 "$jsurl" 2>/dev/null > "$js_content_dir/$fname"
    done < "$js_dir/js_files.txt"

    # -- Endpoints: extract paths from JS content --
    info "Extracting endpoints from JS files..."
    local ep_data; ep_data=$(grep -rhoE "[[:punct:]]([/][a-zA-Z0-9_/.-]{3,})[[:punct:]]" "$js_content_dir/" 2>/dev/null \
        | grep -oE "[/][a-zA-Z0-9_/.-]{3,}" \
        | grep -vE "[.]js$|[.]css$|[.]png$|[.]jpg$|[.]gif$|[.]svg$" \
        | sort -u)
    if [[ -n "$ep_data" ]]; then
        echo "$ep_data" > "$js_dir/endpoints.txt"
        success "Endpoints found in JS: $(wc -l < "$js_dir/endpoints.txt")"
    else
        warn "No endpoints found in JS files."
    fi

    # -- Secrets: search for keys/tokens/passwords in JS --
    info "Searching for secrets and API keys in JS..."
    local sec_data; sec_data=$(grep -rhoiE "(api_key|apikey|secret_key|access_token|auth_token|client_secret|private_key|bearer|password|passwd|AKIA[A-Z0-9]{16}|AIza[0-9A-Za-z_-]{35}|sk-[a-zA-Z0-9]{32,})[[:space:]]*[=:][[:space:]]*[A-Za-z0-9+/._-]{8,}" \
        "$js_content_dir/" 2>/dev/null | sort -u)
    if [[ -n "$sec_data" ]]; then
        echo "$sec_data" > "$js_dir/secrets.txt"
        success "Potential secrets found: $(wc -l < "$js_dir/secrets.txt") -- review manually"
    else
        warn "No secrets found in JS files."
    fi

    # -- Hardcoded URLs and IPs inside JS --
    info "Extracting hardcoded URLs and IPs from JS..."
    local url_data; url_data=$(grep -rhoE "https?://[a-zA-Z0-9._/-]{8,}" "$js_content_dir/" 2>/dev/null | sort -u)
    if [[ -n "$url_data" ]]; then
        echo "$url_data" > "$js_dir/hardcoded_urls.txt"
        success "Hardcoded URLs: $(wc -l < "$js_dir/hardcoded_urls.txt") -> $js_dir/hardcoded_urls.txt"
    else
        warn "No hardcoded URLs found."
    fi

    local ip_data; ip_data=$(grep -rhoE "[0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}" "$js_content_dir/" 2>/dev/null \
        | grep -vE "^0[.]|^127[.]|^255[.]|^10[.]|^192[.]168[.]" | sort -u)
    if [[ -n "$ip_data" ]]; then
        echo "$ip_data" > "$js_dir/hardcoded_ips.txt"
        warn "Hardcoded IPs: $(wc -l < "$js_dir/hardcoded_ips.txt") -> $js_dir/hardcoded_ips.txt"
    else
        warn "No hardcoded IPs found."
    fi

    # Cleanup raw content (already analyzed)
    rm -rf "$js_content_dir"

    find "$js_dir" -type f -empty -delete


    # Cleanup raw content (already analyzed)
    rm -rf "$js_content_dir"

    find "$js_dir" -type f -empty -delete
}

# ─── Print Scan Results ────────────────────────────────────
# ─── Tech Detection ────────────────────────────────────────

tech_detection() {
    local target="$1"
    local domain; domain=$(clean_domain "$target")

    section "Technology Detection"

    info "Detecting technologies with whatweb..."
    whatweb -a 3 --no-errors "http://${domain}" "https://${domain}" 2>/dev/null | grep -v "^$"
}


print_results() {
    local outdir="$1"
    section "Scan Results"

    local vectors=("sqli" "xss" "lfi" "open_redirect" "ssrf" "idor" "rce")

    for v in "${vectors[@]}"; do
        local f="$outdir/${v}.txt"
        if [[ -s "$f" ]]; then
            local count; count=$(wc -l < "$f")
            warn "${v} — $count endpoints -> $f"
        fi
    done

    [[ -s "$outdir/cors.txt" ]]                         && warn "CORS candidates -> $outdir/cors.txt"
    [[ -s "$outdir/cors_vulnerable.txt" ]]              && error "CORS Vulnerable -> $outdir/cors_vulnerable.txt"
    [[ -s "$outdir/js_analysis/secrets.txt" ]]          && warn "JS Secrets -> $outdir/js_analysis/secrets.txt"
    [[ -s "$outdir/js_analysis/endpoints.txt" ]]        && success "JS Endpoints -> $outdir/js_analysis/endpoints.txt"
    [[ -s "$outdir/js_analysis/hardcoded_urls.txt" ]]   && info "JS Hardcoded URLs -> $outdir/js_analysis/hardcoded_urls.txt"
    [[ -s "$outdir/js_analysis/hardcoded_ips.txt" ]]    && warn "JS Hardcoded IPs -> $outdir/js_analysis/hardcoded_ips.txt"
    [[ -s "$outdir/dalfox_results.txt" ]]               && error "XSS Confirmed (dalfox) -> $outdir/dalfox_results.txt"
}

# ─── Module: Full Vulnerability Scan ──────────────────────

run_vuln_scan() {
    clear
    ask "Enter the website URL or domain: "; read website_input
    [[ -z "$website_input" ]] && error "No input provided." && return

    local domain; domain=$(clean_domain "$website_input")
    local outdir="output_${domain}"
    mkdir -p "$outdir"

    clear; tput civis
    section "Full Vulnerability Scan → $domain"

    # Tech detection
    if command -v whatweb &>/dev/null; then
        tech_detection "$website_input" "$outdir"
    else
        warn "whatweb not found. Skipping tech detection. (apt install whatweb)"
    fi

    # URL Collection
    section "URL Collection"
    collect_urls "$website_input" "$outdir"

    if [[ ! -s "$outdir/all_urls.txt" ]]; then
        error "No URLs collected for $domain. Aborting."
        rm -rf "$outdir"; tput cnorm; pause; return
    fi

    # Vuln filtering
    filter_vulns "$outdir/all_urls.txt" "$outdir"

    # JS analysis
    js_analysis "$outdir/all_urls.txt" "$outdir"

    # Print results
    print_results "$outdir"

    tput cnorm; pause
}

# ─── Module: Subdomain Enumeration ────────────────────────

subfinderfun() {
    clear
    ask "Enter the domain (e.g., example.com): "; read domainsub
    [[ -z "$domainsub" ]] && error "No domain provided." && return

    clear; tput civis
    local subdir="subdomains_${domainsub}"
    mkdir -p "$subdir"

    section "Subdomain Enumeration → $domainsub"

    info "Running subfinder..."
    subfinder -d "$domainsub" -all -recursive -silent 2>/dev/null > "$subdir/subfinder.txt"

    info "Deduplicating results..."
    sort -u "$subdir/subfinder.txt" > "$subdir/subdomains.txt"
    rm -f "$subdir/subfinder.txt"

    local total; total=$(wc -l < "$subdir/subdomains.txt")
    success "Total subdomains found: $total"

    info "Probing for active subdomains (httpx-toolkit)..."
    cat "$subdir/subdomains.txt" | httpx-toolkit -ports 80,443,8080,8000,8888,8443 -threads 200 -silent 2>/dev/null \
        | anew "$subdir/active_subdomains.txt" >/dev/null

    local active; active=$(wc -l < "$subdir/active_subdomains.txt" 2>/dev/null || echo 0)

    echo ""
    if [[ -s "$subdir/subdomains.txt" ]]; then
        success "All subdomains ($total): $subdir/subdomains.txt"
        [[ $active -gt 0 ]] && warn "Active subdomains ($active): $subdir/active_subdomains.txt" \
            || error "No active subdomains found."
    else
        error "No subdomains found at all."
        rm -rf "$subdir"
    fi

    tput cnorm; pause
}

# ─── Module: Wayback Machine ───────────────────────────────

fetch_wayback_urls() {
    clear
    ask "Enter the domain (e.g., example.com): "; read domain_input
    [[ -z "$domain_input" ]] && error "No input provided." && return

    local domain; domain=$(clean_domain "$domain_input")
    local dir_name="output_${domain}"
    mkdir -p "$dir_name"

    clear; tput civis
    section "Wayback Machine → $domain"

    info "Fetching all URLs from Wayback Machine..."
    curl -G "https://web.archive.org/cdx/search/cdx" \
        --data-urlencode "url=*.$domain/*" \
        --data-urlencode "collapse=urlkey" \
        --data-urlencode "output=text" \
        --data-urlencode "fl=original" \
        -s -o "$dir_name/all_urls.txt"

    info "Fetching sensitive file extensions..."
    curl -s "https://web.archive.org/cdx/search/cdx?url=*.$domain/*&collapse=urlkey&output=text&fl=original&filter=original:.*\\.(xls|xml|xlsx|json|pdf|sql|doc|docx|pptx|txt|git|zip|tar\\.gz|tgz|bak|7z|rar|log|cache|secret|db|backup|yml|gz|config|csv|yaml|md|md5|exe|dll|bin|ini|bat|sh|tar|deb|rpm|iso|img|env|apk|msi|dmg|tmp|crt|pem|key|pub|asc)$" \
        -o "$dir_name/sensitive_files.txt"

    info "Fetching via waybackurls..."
    echo "$domain" | waybackurls 2>/dev/null | uro | anew "$dir_name/all_urls.txt" >/dev/null

    info "Fetching via gau..."
    echo "$domain" | gau --threads 5 --subs 2>/dev/null | uro | anew "$dir_name/all_urls.txt" >/dev/null

    find "$dir_name" -type f -empty -delete

    if [[ -d "$dir_name" && "$(ls -A "$dir_name" 2>/dev/null)" ]]; then
        success "Results saved in: $dir_name"
        [[ -s "$dir_name/all_urls.txt" ]] && info "Total URLs: $(wc -l < "$dir_name/all_urls.txt")"
        [[ -s "$dir_name/sensitive_files.txt" ]] && warn "Sensitive files: $(wc -l < "$dir_name/sensitive_files.txt") → $dir_name/sensitive_files.txt"
    else
        error "No URLs found for $domain."
        rm -rf "$dir_name"
    fi

    tput cnorm; pause
}

# ─── Module: Nuclei AI Shell ───────────────────────────────

nucleiai() {
    clear; tput cnorm
    section "Nuclei AI Shell"

    nuclei -auth 2>/dev/null

    ask "URL's file: "; read urlfile
    urlfile=$(validate_file "$urlfile")

    while true; do
        echo ""
        ask "Prompt (or 'exit' to go back): "; read prompt
        [[ "$prompt" == "exit" || -z "$prompt" ]] && break
        nuclei -l "$urlfile" -ai "$prompt" 2>/dev/null
    done
}

# ─── Module: Massive Batch Scan ────────────────────────────

scanoutput() {
    clear
    ask "Enter path to the domains/URLs file: "; read outfile
    outfile=$(validate_file "$outfile")

    local total; total=$(wc -l < "$outfile")
    local batch_name; batch_name=$(basename "$outfile" | sed 's/\.[^.]*$//')
    local batch_dir="batch_${batch_name}"
    mkdir -p "$batch_dir"

    clear; tput civis
    section "Massive Batch Scan — $total targets"

    local count=0
    while read -r target; do
        [[ -z "$target" ]] && continue
        ((count++))

        local domain; domain=$(clean_domain "$target")
        local target_dir="$batch_dir/output_${domain}"
        mkdir -p "$target_dir"

        echo ""
        section "[$count/$total] Target: $target"

        collect_urls "$target" "$target_dir"

        if [[ -s "$target_dir/all_urls.txt" ]]; then
            filter_vulns "$target_dir/all_urls.txt" "$target_dir"
            js_analysis "$target_dir/all_urls.txt" "$target_dir"
            print_results "$target_dir"
        else
            error "No URLs found for $target. Skipping."
            rm -rf "$target_dir"
        fi

    done < "$outfile"

    success "Batch scan complete. Results in: $batch_dir"
    tput cnorm; pause
}

# ─── Module: XSS Deep Scan ────────────────────────────────

xss_deep_scan() {
    clear
    section "XSS Deep Scan (dalfox)"

    ask "File of filtered XSS URLs (xss.txt): "; read xss_raw
    xss_raw=$(validate_file "$xss_raw")

    local outdir; outdir=$(dirname "$xss_raw")
    local timestamp; timestamp=$(date +%Y%m%d_%H%M%S)
    local outfile="$outdir/dalfox_results_${timestamp}.txt"

    local xss_count; xss_count=$(wc -l < "$xss_raw")

    clear; tput civis
    section "XSS Deep Scan → $xss_raw"
    info "$xss_count candidate endpoints loaded"

    # Ask optional parameters
    tput cnorm
    echo ""
    ask "Blind XSS callback URL (leave empty to skip): "; read blind_url
    ask "Custom cookie (leave empty to skip): "; read custom_cookie
    ask "Enable deep DOM XSS — slow but thorough [y/N]: "; read use_deep
    echo ""
    tput civis

    # Build dalfox command
    # Core bug bounty flags:
    #   --waf-evasion      → auto-detects WAF and adjusts speed/payloads to evade it
    #   --deep-domxss      → headless browser DOM testing with extended payload set
    #   --follow-redirects → follow 301/302 so redirected params are tested
    #   --mining-dom       → mine parameters from DOM (finds hidden params in JS)
    #   --mining-dict      → bruteforce hidden params with a built-in wordlist
    #   --remote-payloads  → pull fresh payloads from portswigger and payloadbox
    #   --custom-alert-value document.cookie → PoC shows cookie exfil (better for reports)
    #   --format json      → structured output for easier parsing/reporting
    #   --worker 20        → 20 concurrent workers, good balance speed vs stealth
    #   --timeout 30       → 30s per request before giving up
    #   --delay 300        → 300ms between requests to same host, avoids rate limiting

    local dalfox_cmd=(
        dalfox file "$xss_raw"
        --waf-evasion
        --follow-redirects
        --mining-dom
        --mining-dict
        --remote-payloads "portswigger,payloadbox"
        --custom-alert-value "document.cookie"
        --custom-alert-type "str,none"
        --worker 5
        --timeout 10
        --delay 100
        --output "$outfile"
    )

    [[ "$use_deep" =~ ^[yY]$ ]] && dalfox_cmd+=(--deep-domxss)
    [[ -n "$blind_url" ]]       && dalfox_cmd+=(-b "$blind_url")
    [[ -n "$custom_cookie" ]]   && dalfox_cmd+=(-C "$custom_cookie")

    info "Launching dalfox with bug bounty profile..."
    info "Scanning $xss_count URLs — output will appear per result below"
    [[ "$use_deep" =~ ^[yY]$ ]] && warn "Deep DOM mode enabled — this will be slow"
    echo ""

    # Run dalfox with live output (stderr to stdout so progress is visible)
    "${dalfox_cmd[@]}" 2>&1 | tee -a "$outfile.live"
    # Keep only actual findings in the output file
    grep -E "\[POC\]|\[I\]|\[V\]|\[G\]" "$outfile.live" > "$outfile" 2>/dev/null
    rm -f "$outfile.live"

    echo ""
    if [[ -s "$outfile" ]]; then
        warn "Results saved → $outfile"
        echo ""
        # Show only confirmed vuln lines (POC lines)
        local confirmed; confirmed=$(grep -c "\[POC\]" "$outfile" 2>/dev/null || echo 0)
        if [[ $confirmed -gt 0 ]]; then
            error "$confirmed XSS confirmed by dalfox"
            grep "\[POC\]" "$outfile"
        else
            success "No exploitable XSS confirmed."
        fi
    else
        success "No XSS confirmed. Clean results."
        rm -f "$outfile"
    fi

    tput cnorm; pause
}

# ─── Main Menu ─────────────────────────────────────────────

menu() {
    tput cnorm; clear
    banner
    echo -e "${yellowColour}  Vulnerability Scanning${endColour}"
    echo -e "  ${yellowColour}[1]${grayColour} Full scan (XSS, SQLi, LFI, OR, SSRF, CORS, IDOR)${endColour}"
    echo -e "  ${yellowColour}[2]${grayColour} XSS deep scan (dalfox)${endColour}"
    echo ""
    echo -e "${yellowColour}  Reconnaissance${endColour}"
    echo -e "  ${yellowColour}[3]${grayColour} Subdomain enumeration (subfinder)${endColour}"
    echo -e "  ${yellowColour}[4]${grayColour} Wayback Machine + GAU + waymore${endColour}"
    echo ""
    echo -e "${yellowColour}  Advanced${endColour}"
    echo -e "  ${yellowColour}[5]${grayColour} Nuclei AI Shell${endColour}"
    echo -e "  ${yellowColour}[6]${grayColour} Massive batch scan (file of targets)${endColour}"
    echo ""
    echo -e "  ${redColour}[99]${grayColour} Exit${endColour}"
    echo ""
    ask "Select option: "; read option

    case $option in
        1)  run_vuln_scan ;;
        2)  xss_deep_scan ;;
        3)  subfinderfun ;;
        4)  fetch_wayback_urls ;;
        5)  nucleiai ;;
        6)  scanoutput ;;
        99) ctrl_c ;;
        *)  error "Invalid option. Try again." ; sleep 1 ;;
    esac
}

# ─── Entry Point ───────────────────────────────────────────

if [[ $(id -u) -ne 0 ]]; then
    echo -e "${redColour}[!]${grayColour} Must be run as root: sudo $0${endColour}\n"
    exit 1
fi

pathmain=$(pwd)
tput civis; clear
banner
echo -e "${greenColour}[+]${grayColour} Version 3${endColour}"
echo -e "${greenColour}[+]${grayColour} Github: https://github.com/Kidd3n${endColour}"
echo -e "${greenColour}[+]${grayColour} Discord: kidd3n.sh${endColour}"
echo ""
ask "Press Enter to continue"; read
clear
programs

while true; do
    menu
done
