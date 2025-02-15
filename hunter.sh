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
                katana) go install github.com/projectdiscovery/katana/cmd/katana@latest 2>/dev/null ;;
                uro) pipx install uro --force 2>/dev/null ;;
                Gxss) go install github.com/KathanP19/Gxss@latest 2>/dev/null ;;
                kxss) go install github.com/Emoe/kxss@latest 2>/dev/null ;;
                gf) go install github.com/tomnomnom/gf@latest 2>/dev/null ;;
                anew) go install github.com/tomnomnom/anew@latest 2>/dev/null ;;
                httpx) go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest 2>/dev/null ;;
                *) echo -e "${redColour}[-]${grayColour} Could not install: $program. Try installing manually." ;;
            esac
        else
            echo -e "${greenColour}[+]${grayColour} $program is already installed."
            sleep 0.1
        fi
    done
    
    # Copy binaries to /bin/
    sudo cp ~/go/bin/katana /bin/
    sudo cp ~/go/bin/Gxss /bin/
    sudo cp ~/go/bin/kxss /bin/
    sudo cp ~/go/bin/gf /bin/
    sudo cp ~/go/bin/anew /bin/
    sudo cp ~/go/bin/httpx /bin/
    sudo cp ~/.local/bin/uro /bin/
}

# Function to fetch URLs from Wayback Machine
fetch_wayback_urls() {
    echo -ne "${purpleColour}[?]${endColour}${grayColour} Enter the domain (e.g., example.com): ${endColour}"
    read domain
    echo "Fetching all URLs from the Wayback Machine..."
    curl -G "https://web.archive.org/cdx/search/cdx" \
      --data-urlencode "url=*.$domain/*" \
      --data-urlencode "collapse=urlkey" \
      --data-urlencode "output=text" \
      --data-urlencode "fl=original" \
      -o all_urls.txt

    echo "Fetching URLs with specific file extensions..."
    curl "https://web.archive.org/cdx/search/cdx?url=*.$domain/*&collapse=urlkey&output=text&fl=original&filter=original:.*\\.(xls|xml|xlsx|json|pdf|sql|doc|docx|pptx|txt|git|zip|tar\\.gz|tgz|bak|7z|rar|log|cache|secret|db|backup|yml|gz|config|csv|yaml|md|md5|exe|dll|bin|ini|bat|sh|tar|deb|rpm|iso|img|env|apk|msi|dmg|tmp|crt|pem|key|pub|asc)$" \
      -o filtered_urls.txt

    echo "Done! Results saved to:"
    echo "  - all_urls.txt (all URLs)"
    echo "  - filtered_urls.txt (URLs with specific file extensions)"
}

# Function to run vulnerability scanning
run_vuln_scan() {
    echo -ne "${purpleColour}[?]${endColour}${grayColour} Enter the website URL or domain: ${endColour}"
    read website_input
    [[ ! $website_input =~ ^https?:// ]] && website_url="https://$website_input" || website_url="$website_input"
    echo "Normalized URL being used: $website_url"

    output_dir="output"
    mkdir -p "$output_dir"

    echo "Running katana with passive sources (waybackarchive, commoncrawl, alienvault)..."
    echo "$website_url" | katana -ps -pss waybackarchive,commoncrawl,alienvault -f qurl | uro > "$output_dir/output.txt"

    echo "Running katana actively with depth 5..."
    katana -u "$website_url" -d 5 -f qurl | uro | anew "$output_dir/output.txt"
}

menu() {
    tput cnorm
    echo -e "${blueColour}\nSelect an option:${endColour}"
    echo "1) Vulnerability scan"
    echo "2) Fetch URLs from Wayback Machine"
    echo "3) Exit"
    echo -ne "${purpleColour}[?]${endColour}${grayColour} Option: ${endColour}"
    read option

    case $option in
        1) run_vuln_scan ;;
        2) fetch_wayback_urls ;;
        3) exit ;;
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
    echo -e "\n${greenColour}[+]${grayColour} Version 1"
    echo -e "${greenColour}[+]${grayColour} Github: https://github.com/Kidd3n"
    echo -e "${greenColour}[+]${grayColour} Discord ID: kidd3n.sh"
    echo -ne "\n${greenColour}[+]${grayColour} Press Enter to continue" && read
    clear
    programs
    while true; do
        menu
    done
fi


