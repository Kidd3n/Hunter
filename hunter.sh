#!/bin/bash

# Define colors
greenColour="\e[0;32m\033[1m"
endColour="\033[0m\e[0m"
redColour="\e[0;31m\033[1m"
blueColour="\e[0;34m\033[1m"
yellowColour="\e[0;33m\033[1m"
purpleColour="\e[0;35m\033[1m"
turquoiseColour="\e[0;36m\033[1m"
grayColour="\e[0;37m\033[1m"
cleancolor="echo -e \"${endColour}\""

trap ctrl_c INT

ctrl_c() {
    echo -e "\n\n${redColour}[!]${endColour}${grayColour} Exit...${endColour}\n"
    tput cnorm
    exit
}

# Function to check and install Go
programs() {
    echo -e "\n${blueColour}[*]${grayColour} Checking dependencies...\n"
    sleep 0.2
    
    # Check and install Go
    if ! command -v go &> /dev/null; then
        echo -e "${blueColour}[*]${grayColour} Installing Go..."
        sudo apt install -y golang-go 2>/dev/null
    else
        echo -e "${greenColour}[+]${grayColour} Go is already installed."
        sleep 0.1
    fi

    dependencies=(katana uro Gxss kxss gf anew httpx subfinder httpx-toolkit nuclei subzy)

    for program in "${dependencies[@]}"; do
        if ! command -v $program &> /dev/null; then
            echo -e "${blueColour}[*]${grayColour} Installing ${program}..."
            case $program in
                katana) go install github.com/projectdiscovery/katana/cmd/katana@latest 2>/dev/null; sudo cp ~/go/bin/katana /bin/ ;;
                uro) pipx install uro --force 2>/dev/null; sudo cp ~/.local/bin/uro /bin/ ;;
                Gxss) go install github.com/KathanP19/Gxss@latest 2>/dev/null; sudo cp ~/go/bin/Gxss /bin/ ;;
                kxss) go install github.com/Emoe/kxss@latest 2>/dev/null; sudo cp ~/go/bin/kxss /bin/ ;;
                gf) go install github.com/tomnomnom/gf@latest 2>/dev/null; sudo cp ~/go/bin/gf /bin/ ;;
                anew) go install github.com/tomnomnom/anew@latest 2>/dev/null; sudo cp ~/go/bin/anew /bin/ ;;
                httpx) go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest 2>/dev/null; sudo cp ~/go/bin/httpx /bin/ ;;
                subfinder) go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest 2>/dev/null; sudo cp ~/go/bin/subfinder /bin/ ;;
                httpx-toolkit) sudo apt install httpx-toolkit -y ;;
                nuclei) go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest 2>/dev/null; sudo cp ~/go/bin/nuclei /bin/ ;;
                subzy) go install -v github.com/PentestPad/subzy@latest 2>/dev/null; sudo cp ~/go/bin/subzy /bin/ ;;
                *) echo -e "${redColour}[-]${grayColour} Could not install: $program. Try installing manually." ;;
            esac
        else
            echo -e "${greenColour}[+]${grayColour} $program is already installed."
            sleep 0.1
        fi
    done

    if ls ~/.gf/sqli.json &>/dev/null; then
        echo -e "${greenColour}[+]${grayColour} gf patterns is already installed."
        sleep 0.1
    else    
        echo -e "${blueColour}[*]${grayColour} Installing gf patterns..."
        git clone https://github.com/coffinxp/GFpattren.git 2>/dev/null
        sleep 3
        mkdir ~/.gf
        mv GFpattren/*.json ~/.gf 2>/dev/null
        rm -rf GFpattren 2>/dev/null
    fi

    clear 
}

gfpinstall() {
    if ls ~/.gf/sqli.json &>/dev/null; then
         echo -e "${blueColour}${grayColour}"
    else    
        echo -e "${blueColour}[*]${grayColour} Installing gf patterns..."
        git clone https://github.com/coffinxp/GFpattren.git 2>/dev/null
        sleep 3
        mkdir ~/.gf
        mv GFpattren/*.json ~/.gf 2>/dev/null
        rm -rf GFpattren 2>/dev/null
    fi
}
# Function to fetch URLs from Wayback Machine
fetch_wayback_urls() {
    clear; echo -ne "${purpleColour}[?]${endColour}${grayColour} Enter the domain (e.g., example.com): ${endColour}"
    read domain_input
    
    domain=$(echo "$domain_input" | sed -e 's|^[^/]*//||' -e 's|/.*$||')
    dir_name="output_${domain}"
    mkdir -p "$dir_name"

    clear; tput civis
    echo -e "\n${blueColour}[*]${grayColour} Fetching all URLs from Wayback Machine..."
    curl -G "https://web.archive.org/cdx/search/cdx" \
      --data-urlencode "url=*.$domain/*" \
      --data-urlencode "collapse=urlkey" \
      --data-urlencode "output=text" \
      --data-urlencode "fl=original" \
      -s -o "$dir_name/all_urls.txt"

    echo -e "\n${blueColour}[*]${grayColour} Fetching sensitive extensions..."
    curl -s "https://web.archive.org/cdx/search/cdx?url=*.$domain/*&collapse=urlkey&output=text&fl=original&filter=original:.*\\.(xls|xml|xlsx|json|pdf|sql|doc|docx|pptx|txt|git|zip|tar\\.gz|tgz|bak|7z|rar|log|cache|secret|db|backup|yml|gz|config|csv|yaml|md|md5|exe|dll|bin|ini|bat|sh|tar|deb|rpm|iso|img|env|apk|msi|dmg|tmp|crt|pem|key|pub|asc)$" \
      -o "$dir_name/filtered_urls.txt"

    [[ ! -s "$dir_name/all_urls.txt" ]] && rm "$dir_name/all_urls.txt" 2>/dev/null
    [[ ! -s "$dir_name/filtered_urls.txt" ]] && rm "$dir_name/filtered_urls.txt" 2>/dev/null

    if [[ -d "$dir_name" && "$(ls -A $dir_name 2>/dev/null)" ]]; then
        echo -e "\n${greenColour}[*]${grayColour} Results saved in: $dir_name"
    else
        echo -e "\n${redColour}[!]${grayColour} No URLs found for this domain."
        rm -rf "$dir_name" 2>/dev/null
    fi
    echo -ne "\n\n${blueColour}[+]${grayColour} Press Enter to continue" && read
    tput cnorm
}

scanoutput() {
    clear; echo -ne "${purpleColour}[?]${grayColour} Enter path to the domains/URLs file: "
    read outfile

    if [[ ! -s "$outfile" ]]; then
        echo -e "\n${redColour}[!]${grayColour} File empty or not found."
        sleep 2; return
    fi

    batch_name=$(basename "$outfile" | sed 's/\.[^.]*$//')
    batch_dir="batch_${batch_name}"
    mkdir -p "$batch_dir"

    echo -e "\n${blueColour}[*]${grayColour} Starting massive scan for $(wc -l < "$outfile") targets..."
    sleep 1

    while read -r target; do
        [[ -z "$target" ]] && continue

        domain_clean=$(echo "$target" | sed -e 's|^[^/]*//||' -e 's|/.*$||')
        target_dir="$batch_dir/output_${domain_clean}"
        mkdir -p "$target_dir"

        echo -e "\n${yellowColour}--------------------------------------------------${endColour}"
        echo -e "${purpleColour}[>] Target:${grayColour} $target"
        
        echo -e "${blueColour}[*]${grayColour} Collecting URLs with Katana..."
        echo "$target" | katana -ps -pss waybackarchive,commoncrawl,alienvault -jc -f qurl -silent | uro > "$target_dir/all_urls.txt"
        katana -u "$target" -d 3 -jc -f qurl -silent | uro | anew "$target_dir/all_urls.txt" 

        if [[ -s "$target_dir/all_urls.txt" ]]; then
            gfpinstall
            echo -e "${greenColour}[!]${grayColour} Filtering potential endpoints..."
            
            cat "$target_dir/all_urls.txt" | gf sqli | sed 's/=.*/=/' | anew "$target_dir/sqli.txt" 
            cat "$target_dir/all_urls.txt" | Gxss | kxss | grep -oP '^URL: \K\S+' | sed 's/=.*/=/' | anew "$target_dir/xss.txt" 
            cat "$target_dir/all_urls.txt" | gf lfi | sed 's/=.*/=/' | anew "$target_dir/lfi.txt" 
            cat "$target_dir/all_urls.txt" | gf or | sed 's/=.*/=/' | anew "$target_dir/open_redirect.txt" 

            # Limpiar archivos vacíos
            find "$target_dir" -type f -empty -delete
            echo -e "${greenColour}[+]${grayColour} Done! Results in $target_dir"
        else
            echo -e "${redColour}[!]${grayColour} No URLs found for $target"
            rm -rf "$target_dir"
        fi

    done < "$outfile"

    echo -ne "\n\n${blueColour}[+++]${grayColour} Massive scan completed. Check folder: $batch_dir"
    echo -ne "\n${blueColour}[+]${grayColour} Press Enter to continue" && read
    tput cnorm
}

# Function to run vulnerability scanning
run_vuln_scan() {
    clear; echo -ne "${purpleColour}[?]${grayColour} Enter the website URL or domain: "
    read website_input
   
    domain_clean=$(echo "$website_input" | sed -e 's|^[^/]*//||' -e 's|/.*$||')
    output_dir="output_${domain_clean}"
    mkdir -p "$output_dir"

    [[ ! $website_input =~ ^https?:// ]] && website_url="https://$website_input" || website_url="$website_input"
    clear; tput civis
    echo -ne "${blueColour}[!]${grayColour} Normalized URL being used: $website_url"

    echo -e "\n\n${blueColour}[*]${grayColour} Running katana with passive sources..."
    echo "$website_url" | katana -ps -pss waybackarchive,commoncrawl,alienvault -jc -f qurl | uro > "$output_dir/output.txt"

    echo -e "${blueColour}[*]${grayColour} Running katana actively..."
    katana -u "$website_url" -d 5 -jc -f qurl | uro | anew "$output_dir/output.txt"

    katana_file="$output_dir/output.txt"

    if [[ ! -s "$katana_file" ]]; then
        rm "$katana_file" 2>/dev/null
        echo -e "\n${redColour}[!]${grayColour} No URLs collected."
        sleep 3; return
    fi

    
    gfpinstall
    echo -e "\n${greenColour}[!]${grayColour} Filtering SQLi..."; sqli_file="$output_dir/sqli.txt"
    cat "$katana_file" | gf sqli | sed 's/=.*/=/' | anew "$sqli_file" 

    echo -e "${greenColour}[!]${grayColour} Filtering XSS..."; xss_file="$output_dir/xss.txt"
    cat "$katana_file" | Gxss | kxss | grep -oP '^URL: \K\S+' | sed 's/=.*/=/' | anew "$xss_file" 
    
    echo -e "${greenColour}[!]${grayColour} Filtering LFI..."; lfi_file="$output_dir/lfi.txt"
    cat "$katana_file" | gf lfi | sed 's/=.*/=/' | anew "$lfi_file" 

    echo -e "${greenColour}[!]${grayColour} Filtering OR..."; or_file="$output_dir/open_redirect.txt"
    cat "$katana_file" | gf or | sed 's/=.*/=/' | anew "$or_file" 


    for file in "$xss_file" "$or_file" "$lfi_file" "$sqli_file"; do
        [[ ! -s "$file" ]] && rm "$file" 2>/dev/null
    done

    echo -ne "\n\n${yellowColour}[!]${grayColour} Results in '$output_dir':\n"
    [[ -s "$xss_file" ]] && echo -e "${greenColour}[+]${grayColour} XSS: $xss_file"
    [[ -s "$or_file" ]] && echo -e "${greenColour}[+]${grayColour} OR: $or_file"
    [[ -s "$lfi_file" ]] && echo -e "${greenColour}[+]${grayColour} LFI: $lfi_file"
    [[ -s "$sqli_file" ]] && echo -e "${greenColour}[+]${grayColour} SQLi: $sqli_file"

    echo -ne "\n${blueColour}[+]${grayColour} Press Enter to continue" && read
    tput cnorm
}

subfinderfun() {
    clear
    echo -ne "${purpleColour}[?]${endColour}${grayColour} Enter the domain (e.g., example.com): " && read domainsub
    clear; tput civis
    subdir="subdomains_${domainsub}"
    mkdir -p "$subdir"
    sleep 1

    echo -ne "\n${blueColour}[*]${grayColour} Finding subdomains in $domainsub..."
    subfinder -d "$domainsub" -all -recursive > "$subdir/subdomains.txt"

    echo -ne "\n${blueColour}[*]${grayColour} Filtering active subdomains..."
    cat "$subdir/subdomains.txt" | httpx-toolkit -ports 80,443,8080,8000,8888 -threads 200 | anew "$subdir/active_subdomains.txt"

    echo -e "\n${redColour}[!]${grayColour} Subdomain results for ${domainsub}:"

    
    if [[ -s "$subdir/subdomains.txt" ]]; then
        echo -ne "\n${blueColour}[+]${grayColour}${yellowColour} All${grayColour} subdomains: $subdir/subdomains.txt"
        if [[ -s "$subdir/active_subdomains.txt" ]]; then
            echo -ne "\n${blueColour}[+]${grayColour}${greenColour} Active${grayColour} subdomains: $subdir/active_subdomains.txt"
        else
            echo -ne "\n${redColour}[!]${grayColour} No active subdomains found (check subdomains.txt manually)."
        fi
    else
        echo -ne "\n${redColour}[!]${grayColour} No subdomains found at all."
        rm -rf "$subdir" 2>/dev/null
    fi

    echo -ne "\n\n${blueColour}[+]${grayColour} Press Enter to continue" && read
    tput cnorm
}

checktemp() {
    pathtemp=$(find / -type f -name "detect-all-takeovers.yaml" -print -quit 2>/dev/null)
    if [[ -n "$pathtemp" ]]; then
        echo -ne "\n${blueColour}[*]${grayColour} Find takeovers with nuclei..."
        nuclei -t $pathtemp -l $pathsubact
        echo -ne "\n\n${blueColour}[+]${grayColour} Press Enter to continue" && read
        tput cnorm
    else
        echo -ne "\n${greenColour}[+]${grayColour} Downloading the nuclei template."
        wget https://raw.githubusercontent.com/coffinxp/nuclei-templates/refs/heads/main/detect-all-takeovers.yaml 2>/dev/null
        checktemp
    fi
}

takeoversubfun() {
    clear
    echo -ne "${purpleColour}[?]${endColour}${grayColour} Enter the path to the file with the active subdomains: " && read pathsubact
    subzy run --targets $pathsubact --concurrency 100 --hide_fails --verify_ssl 
    checktemp
    echo -ne "\n\n${blueColour}[+]${grayColour} Press Enter to continue" && read
    tput cnorm

}
validate_file() {
    while [[ ! -f "$1" ]]; do
        echo -e "${redColour}[!]${grayColour} The file '$1' does not exist. Please enter a valid file."
        echo -ne "${yellowColour}[?]${grayColour} URL's file: "
        read urlsfile
        set -- "$urlsfile"
    done
    return 0
}

nucleiai(){
    tput cnorm

    nuclei -auth

    main() {
        tput cnorm
    
        if [[ -z "$urlfile" ]]; then
            echo -ne "\n${yellowColour}[?]${grayColour} URL's file: "
            read urlfile

            
            validate_file "$urlfile"
        fi

        echo -ne "\n${blueColour}[?]${grayColour} Prompt: "
        read prompt

        nuclei -l "$urlfile" -ai "$prompt"
        main
    }

    main 
}

menu() {
    tput cnorm; clear
    echo -ne "${redColour}"
    echo -ne "                    _            \n"
    echo -ne "  /\\  /\\_   _ _ __ | |_ ___ _ __ \n"
    echo -ne " / /_/ / | | | '_ \\| __/ _ \\ '__|\n"
    echo -ne "/ __  /| |_| | | | | ||  __/ |   \n"
    echo -ne "\\/ /_/  \\__,_|_| |_|\\__\\___|_|   \n"
    echo -e "\n\n${yellowColour}[1]${grayColour} Scan endpoints (XSS, SQLI, LFI, OR)"
    echo -e "${yellowColour}[2]${grayColour} Scan subdomains"
    echo -e "${yellowColour}[3]${grayColour} Scan URL Wayback Machine"
    echo -e "${yellowColour}[4]${grayColour} Scan Takeovers"
    echo -e "${yellowColour}[5]${grayColour} Shell Nuclei AI"
    echo -e "${yellowColour}[6]${grayColour} Scan of urls file"
    echo -e "\n${redColour}[99]${grayColour} Exit"
    echo -ne "\n${blueColour}[?]${grayColour} Attack: " && read option

    case $option in
        1) run_vuln_scan ;;
        2) subfinderfun ;;
        3) fetch_wayback_urls ;;
        4) takeoversubfun ;;
        5) nucleiai ;;
        6) scanoutput ;;
        99) ctrl_c ;;
        *) echo -e "${redColour}Invalid option, try again.${endColour}" ;;
    esac
}

# Check if the tool was run as root
if [ $(id -u) -ne 0 ]; then
    echo -e "${redColour}\n[!]${grayColour} Must be root (sudo $0)\n"
    $cleancolor
    exit 1
# If the tool was run as root, run the update packages, check dependencies and run the main code
else
    pathmain=$(pwd)
    tput civis; clear
    echo -ne "${redColour}"
    echo -ne "                    _            \n"
    echo -ne "  /\\  /\\_   _ _ __ | |_ ___ _ __ \n"
    echo -ne " / /_/ / | | | '_ \\| __/ _ \\ '__|\n"
    echo -ne "/ __  /| |_| | | | | ||  __/ |   \n"
    echo -ne "\\/ /_/  \\__,_|_| |_|\\__\\___|_|   \n"
    echo -e "\n${greenColour}[+]${grayColour} Version 2"
    echo -e "${greenColour}[+]${grayColour} Github: https://github.com/Kidd3n"
    echo -e "${greenColour}[+]${grayColour} Discord ID: kidd3n.sh"
    echo -ne "\n${greenColour}[+]${grayColour} Press Enter to continue" && read
    clear
    programs
    while true; do
        menu
    done
fi