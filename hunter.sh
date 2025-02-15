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
    sleep 0.3
    
    # Check and install Go
    if ! command -v go &> /dev/null; then
        echo -e "${blueColour}[*]${grayColour} Installing Go..."
        sudo apt install -y golang-go 2>/dev/null
    else
        echo -e "${greenColour}[+]${grayColour} Go is already installed."
        sleep 0.1
    fi
    
    dependencies=(katana uro Gxss kxss gf anew httpx subfinder)

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
                subfinder) go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest; sudo cp ~/go/bin/subfinder /bin/ ;;
                *) echo -e "${redColour}[-]${grayColour} Could not install: $program. Try installing manually." ;;
            esac
        else
            echo -e "${greenColour}[+]${grayColour} $program is already installed."
            sleep 0.1
        fi
    done
    
    clear
}

# Function to fetch URLs from Wayback Machine
fetch_wayback_urls() {
    clear; echo -ne "${purpleColour}[?]${endColour}${grayColour} Enter the domain (e.g., example.com): ${endColour}"
    read domain
    echo -e "\n${blueColour}[*]${grayColour} Fetching all URLs from the Wayback Machine..."
    curl -G "https://web.archive.org/cdx/search/cdx" \
      --data-urlencode "url=*.$domain/*" \
      --data-urlencode "collapse=urlkey" \
      --data-urlencode "output=text" \
      --data-urlencode "fl=original" \
      -o output/all_urls.txt

    echo -e "\n${blueColour}[*]${grayColour} Fetching URLs with specific file extensions..."
    curl "https://web.archive.org/cdx/search/cdx?url=*.$domain/*&collapse=urlkey&output=text&fl=original&filter=original:.*\\.(xls|xml|xlsx|json|pdf|sql|doc|docx|pptx|txt|git|zip|tar\\.gz|tgz|bak|7z|rar|log|cache|secret|db|backup|yml|gz|config|csv|yaml|md|md5|exe|dll|bin|ini|bat|sh|tar|deb|rpm|iso|img|env|apk|msi|dmg|tmp|crt|pem|key|pub|asc)$" \
      -o output/filtered_urls.txt

    echo -ne "${greenColour}[!]${grayColour} Done! Results saved to:"
    echo -ne "${greenColour}[+]${grayColour}  output/all_urls.txt (all URLs)"
    echo -ne "${greenColour}[+]${grayColour}  output/filtered_urls.txt (URLs with specific file extensions)\n"
    echo -ne "\n\n${blueColour}[+]${grayColour} Press Enter to continue" && read
}

# Function to run vulnerability scanning
run_vuln_scan() {
    clear; echo -ne "${purpleColour}[?]${grayColour} Enter the website URL or domain: "
    read website_input
    [[ ! $website_input =~ ^https?:// ]] && website_url="https://$website_input" || website_url="$website_input"
    clear; tput civis
    echo -ne "${blueColour}[!]${grayColour} Normalized URL being used: $website_url"

    output_dir="output"
    mkdir -p "$output_dir"

    echo -e "\n\n${blueColour}[*]${grayColour} Running katana with passive sources (waybackarchive, commoncrawl, alienvault)..."
    echo "$website_url" | katana -ps -pss waybackarchive,commoncrawl,alienvault -f qurl | uro > "$output_dir/output.txt"

    echo -e "${blueColour}[*]${grayColour} Running katana actively with depth 5..."
    katana -u "$website_url" -d 5 -f qurl | uro | anew "$output_dir/output.txt"

    echo -e "\n${greenColour}[!]${grayColour} Filtering URLs for potential XSS endpoints..."; sleep 1
    
    # XSS
    cat "$output_dir/output.txt" | Gxss | kxss | grep -oP '^URL: \K\S+' | sed 's/=.*/=/' | sort -u > "$output_dir/xss_output.txt"
    echo -e "${blueColour}[*]${grayColour} Extracting final filtered URLs to $output_dir/xss_output.txt..."

    # Open Redirect
    echo -e "${greenColour}[!]${grayColour} Filtering URLs for potential Open Redirect endpoints..."
    cat "$output_dir/output.txt" | gf or | sed 's/=.*/=/' | sort -u > "$output_dir/open_redirect_output.txt"

    # LFI
    echo -e "${greenColour}[!]${grayColour} Filtering URLs for potential LFI endpoints..."
    cat "$output_dir/output.txt" | gf lfi | sed 's/=.*/=/' | sort -u > "$output_dir/lfi_output.txt"

    # SQLi
    echo -e "${greenColour}[!]${grayColour} Filtering URLs for potential SQLi endpoints..."
    cat "$output_dir/output.txt" | gf sqli | sed 's/=.*/=/' | sort -u > "$output_dir/sqli_output.txt"

    # Remove the intermediate file output/output.txt
    rm "$output_dir/output.txt"
    
    echo -ne "\n${redColour}[!]${grayColour} Filtered URLs have been saved to the respective output files in the 'output' directory:\n"
    echo -ne "\n${greenColour}[+]${grayColour}  XSS: $output_dir/xss_output.txt"
    echo -ne "\n${greenColour}[+]${grayColour}  Open Redirect: $output_dir/open_redirect_output.txt"
    echo -ne "\n${greenColour}[+]${grayColour}  LFI: $output_dir/lfi_output.txt"
    echo -ne "\n${greenColour}[+]${grayColour}  SQLi: $output_dir/sqli_output.txt\n\n\n"
    echo -ne "\n\n${blueColour}[+]${grayColour} Press Enter to continue" && read
    tput cnorm
}

subfinderfun() {
    subdir="subdomains"
    mkdir -p "$subdir"
    clear; echo -ne "${purpleColour}[?]${endColour}${grayColour} Enter the domain (e.g., example.com): " && read domainsub
    sleep 1
    echo -ne "\n${blueColour}[*]${grayColour} Finding subdomains in $domainsub"
    subfinder -d $domainsub -all -recursive > $subdir/subdomains.txt
    echo -ne "\n${blueColour}[*]${grayColour} Filtering active subdomains"
    cat "$subdir/subdomains.txt" | httpx-toolkit -ports 80,443,8080,8000,8888 -threads 200 > $subdir/subdomains_live.txt
    echo -ne "\n${redColour}[!]${grayColour} The ${greenColour}subdomains${grayColour} of ${domainsub} have been saved to the respective output files in the 'output' directory:\n"
    echo -ne "\n${blueColour}[+]${grayColour}${yellowColour}All${grayColour} subdomains: $subdir/subdomains.txt"
    echo -ne "\n${blueColour}[+]${grayColour}${greenColour}Active${grayColour} subdomains: $subdir/subdomains_live.txt"
    echo -ne "\n\n${blueColour}[+]${grayColour} Press Enter to continue" && read
}

menu() {
    tput cnorm; clear
    echo -ne "${redColour}"
    echo -ne "                    _            \n"
    echo -ne "  /\\  /\\_   _ _ __ | |_ ___ _ __ \n"
    echo -ne " / /_/ / | | | '_ \\| __/ _ \\ '__|\n"
    echo -ne "/ __  /| |_| | | | | ||  __/ |   \n"
    echo -ne "\\/ /_/  \\__,_|_| |_|\\__\\___|_|   \n"
    echo -e "\n\n${yellowColour}[1]${grayColour} Scan endpoints (XSS, SQLI, LFI, OP)"
    echo -e "${yellowColour}[2]${grayColour} Scan subdomains"
    echo -e "${yellowColour}[3]${grayColour} Scan URL Wayback Machine"
    echo -e "\n${redColour}[99]${grayColour} Exit"
    echo -ne "\n${blueColour}[?]${grayColour} Attack: " && read option

    case $option in
        1) run_vuln_scan ;;
        2) subfinderfun ;;
        3) fetch_wayback_urls ;;
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