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
    exit
}

# Function to check and install Go
programs() {
    echo -e "\n${blueColour}[*]${grayColour} Checking dependencies...\n"
    sleep 0.3
    
    # Check and install Go
    if ! command -v go &> /dev/null; then
        echo -e "${blueColour}[*]${grayColour} Installing Go..."
        sudo apt install -y golang-go 2>/dev/null
    else
        echo -e "${greenColour}[+]${grayColour} Go is already installed."
        sleep 0.1
    fi
    
    dependencies=(katana uro Gxss kxss gf anew httpx)

    for program in "${dependencies[@]}"; do
        if ! command -v $program &> /dev/null; then
            echo -e "${blueColour}[*]${grayColour} Installing ${program}..."
            case $program in
                katana) go install github.com/projectdiscovery/katana/cmd/katana@latest; sudo cp ~/go/bin/katana /bin/ 2>/dev/null ;;
                uro) pipx install uro --force; sudo cp ~/.local/bin/uro /bin/ 2>/dev/null ;;
                Gxss) go install github.com/KathanP19/Gxss@latest; sudo cp ~/go/bin/Gxss /bin/ 2>/dev/null ;;
                kxss) go install github.com/Emoe/kxss@latest; sudo cp ~/go/bin/kxss /bin/ 2>/dev/null ;;
                gf) go install github.com/tomnomnom/gf@latest; sudo cp ~/go/bin/gf /bin/ 2>/dev/null ;;
                anew) go install github.com/tomnomnom/anew@latest; sudo cp ~/go/bin/anew /bin/ 2>/dev/null ;;
                httpx) go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest; sudo cp ~/go/bin/httpx /bin/ 2>/dev/null ;;
                *) echo -e "${redColour}[-]${grayColour} Could not install: $program. Try installing manually." ;;
            esac
        else
            echo -e "${greenColour}[+]${grayColour} $program is already installed."
            sleep 0.1
        fi
    done
    
    # Copy binaries to /bin/
    #sudo cp ~/go/bin/katana /bin/
    #sudo cp ~/go/bin/Gxss /bin/
    #sudo cp ~/go/bin/kxss /bin/
    #sudo cp ~/go/bin/gf /bin/
    #sudo cp ~/go/bin/anew /bin/
    #sudo cp ~/go/bin/httpx /bin/
    #sudo cp ~/.local/bin/uro /bin/
    clear
}

# Function to fetch URLs from Wayback Machine
fetch_wayback_urls() {
    clear; echo -ne "${purpleColour}[?]${endColour}${grayColour} Enter the domain (e.g., example.com): ${endColour}"
    read domain
    echo "\n{$blueColour}[*]{$grayColour} Fetching all URLs from the Wayback Machine..."
    curl -G "https://web.archive.org/cdx/search/cdx" \
      --data-urlencode "url=*.$domain/*" \
      --data-urlencode "collapse=urlkey" \
      --data-urlencode "output=text" \
      --data-urlencode "fl=original" \
      -o output/WBall_urls.txt

    echo "\n${blueColour}[*]${grayColour} Fetching URLs with specific file extensions..."
    curl "https://web.archive.org/cdx/search/cdx?url=*.$domain/*&collapse=urlkey&output=text&fl=original&filter=original:.*\\.(xls|xml|xlsx|json|pdf|sql|doc|docx|pptx|txt|git|zip|tar\\.gz|tgz|bak|7z|rar|log|cache|secret|db|backup|yml|gz|config|csv|yaml|md|md5|exe|dll|bin|ini|bat|sh|tar|deb|rpm|iso|img|env|apk|msi|dmg|tmp|crt|pem|key|pub|asc)$" \
      -o output/WBfiltered_urls.txt

    echo -ne "${greenColour}[!]${grayColour} Done! Results saved to:"
    echo -ne "${greenColour}[+]${grayColour}  - all_urls.txt (all URLs)"
    echo -ne "${greenColour}[+]${grayColour}  - filtered_urls.txt (URLs with specific file extensions)"
}

# Function to run vulnerability scanning
run_vuln_scan() {
    clear; echo -ne "${purpleColour}[?]${grayColour} Enter the website URL or domain: ${endColour}"
    read website_input
    [[ ! $website_input =~ ^https?:// ]] && website_url="https://$website_input" || website_url="$website_input"
    clear; tput civis
    echo -ne "${blueColour}[!]${grayColour} Normalized URL being used: $website_url"

    output_dir="output"
    mkdir -p "$output_dir"

    echo "${blueColour}[*]${grayColour} Running katana with passive sources (waybackarchive, commoncrawl, alienvault)..."
    echo "$website_url" | katana -ps -pss waybackarchive,commoncrawl,alienvault -f qurl | uro > "$output_dir/output.txt"

    echo "${blueColour}[*]${grayColour} Running katana actively with depth 5..."
    katana -u "$website_url" -d 5 -f qurl | uro | anew "$output_dir/output.txt"

    echo "\n${greenColour}[!]${grayColour} Filtering URLs for potential XSS endpoints..."; sleep 1
    
    # XSS
    cat "$output_dir/output.txt" | Gxss | kxss | grep -oP '^URL: \K\S+' | sed 's/=.*/=/' | sort -u > "$output_dir/xss_output.txt"
    echo "${blueColour}[*]${grayColour} Extracting final filtered URLs to $output_dir/xss_output.txt..."

    # Open Redirect
    echo "${greenColour}[!]${grayColour} Filtering URLs for potential Open Redirect endpoints..."
    cat "$output_dir/output.txt" | gf or | sed 's/=.*/=/' | sort -u > "$output_dir/open_redirect_output.txt"

    # LFI
    echo "${greenColour}[!]${grayColour} Filtering URLs for potential LFI endpoints..."
    cat "$output_dir/output.txt" | gf lfi | sed 's/=.*/=/' | sort -u > "$output_dir/lfi_output.txt"

    # SQLi
    echo "{$greenColour}[!]${grayColour} Filtering URLs for potential SQLi endpoints..."
    cat "$output_dir/output.txt" | gf sqli | sed 's/=.*/=/' | sort -u > "$output_dir/sqli_output.txt"

    # Remove the intermediate file output/output.txt
    rm "$output_dir/output.txt"
    
    echo -ne "\n${greenColour}[!]${grayColour} Filtered URLs have been saved to the respective output files in the 'output' directory:\n"
    echo -ne "${greenColour}[+]${grayColour}  XSS: $output_dir/xss_output.txt"
    echo -ne "${greenColour}[+]${grayColour}  Open Redirect: $output_dir/open_redirect_output.txt"
    echo -ne "${greenColour}[+]${grayColour}  LFI: $output_dir/lfi_output.txt"
    echo -ne "${greenColour}[+]${grayColour}  SQLi: $output_dir/sqli_output.txt"
    tput cnorm
}

menu() {
    tput cnorm
    echo -ne "${yellowColour}[!]${grayColour} Attacks:\n"
    echo "[1] Scan End Points"
    echo "[2] Scan URL Wayback Machine"
    echo "[99] Exit\n"
    echo -ne "${blueColour}[?]${grayColour} Attack: " && read option

    case $option in
        1) run_vuln_scan ;;
        2) fetch_wayback_urls ;;
        99) exit ;;
        *) echo -e "${redColour}Invalid option, try again.${endColour}" ;;
    esac
}

# Check if the tool was run as root
if [ $(id -u) -ne 0 ]; then
    echo -e "$redColour\n[!]$grayColour Must be root (sudo $0)\n"
    $cleancolor
    exit 1
# If the tool was run as root, run the update packages, check dependencies and run the main code
else
    pathmain=$(pwd)
    tput civis; clear
    echo -e "${turquoiseColour}"
    echo -e "${greenColour}[+]${grayColour} Version 1"
    echo -e "${greenColour}[+]${grayColour} Github: https://github.com/Kidd3n"
    echo -e "${greenColour}[+]${grayColour} Discord ID: kidd3n.sh"
    echo -ne "\n${greenColour}[+]${grayColour} Press Enter to continue" && read
    clear
    programs
    while true; do
        menu
    done
fi


