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
    sudo rm -rf output_https:
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
    read domain
    clear; tput civis
    echo -e "\n${blueColour}[*]${grayColour} Fetching all URLs from the Wayback Machine..."
    curl -G "https://web.archive.org/cdx/search/cdx" \
      --data-urlencode "url=*.$domain/*" \
      --data-urlencode "collapse=urlkey" \
      --data-urlencode "output=text" \
      --data-urlencode "fl=original" \
      -o output_${domain}/all_urls.txt


    echo -e "\n${blueColour}[*]${grayColour} Fetching URLs with specific file extensions..."
    curl "https://web.archive.org/cdx/search/cdx?url=*.$domain/*&collapse=urlkey&output=text&fl=original&filter=original:.*\\.(xls|xml|xlsx|json|pdf|sql|doc|docx|pptx|txt|git|zip|tar\\.gz|tgz|bak|7z|rar|log|cache|secret|db|backup|yml|gz|config|csv|yaml|md|md5|exe|dll|bin|ini|bat|sh|tar|deb|rpm|iso|img|env|apk|msi|dmg|tmp|crt|pem|key|pub|asc)$" \
      -o output_${domain}/filtered_urls.txt

    [[ ! -s output_${domain}/all_urls.txt ]] && rm output/all_urls.txt
    [[ ! -s output_${domain}/filtered_urls.txt ]] && rm output/filtered_urls.txt

    if [[ -s output_${domain}/all_urls.txt || -s output_${domain}/filtered_urls.txt ]]; then
        echo -e "\n${greenColour}[*]${grayColour} Results saved to:"
        [[ -s output_${domain}/all_urls.txt ]] && echo -ne "\n${greenColour}[+]${grayColour}  output_${domain}/all_urls.txt (all URLs)"
        [[ -s output_${domain}/filtered_urls.txt ]] && echo -ne "\n${greenColour}[+]${grayColour}  output_${domain}/filtered_urls.txt (URLs with specific file extensions)"
    else
        echo -e "\n${redColour}[!]${grayColour} No results found. No URLs were extracted."
        sudo rm -rf output_${domain}
    fi
    echo -ne "\n\n${blueColour}[+]${grayColour} Press Enter to continue" && read
    tput cnorm
}

scanoutput() {
    clear; echo -ne "${purpleColour}[?]${grayColour} Enter output file: "
    read outfile

    if [[ ! -s "$outfile" ]]; then
        sudo rm "$outfile"
        echo -e "\n${redColour}[!]${grayColour} No URLs were collected. Exiting..."
        sleep 3; menu
    fi

    # SQLi
    gfpinstall
    echo -e "\n${greenColour}[!]${grayColour} Filtering URLs for potential SQLi endpoints...\n"; sleep 1
    sqli_file="$output_dir/sqli_output.txt"
    cat "$outfile" | gf sqli | sed 's/=.*/=/' 

    # XSS
    echo -e "\n${greenColour}[!]${grayColour} Filtering URLs for potential XSS endpoints...\n"; sleep 1
    xss_file="$output_dir/xss_output.txt"
    cat "$outfile" | Gxss | kxss | grep -oP '^URL: \K\S+' | sed 's/=.*/=/'
    
    # LFI
    echo -e "\n${greenColour}[!]${grayColour} Filtering URLs for potential LFI endpoints...\n"; sleep 1
    lfi_file="$output_dir/lfi_output.txt"
    cat "$outfile" | gf lfi | sed 's/=.*/=/'

    # Open Redirect
    echo -e "\n${greenColour}[!]${grayColour} Filtering URLs for potential OR endpoints...\n"; sleep 1
    or_file="$output_dir/open_redirect_output.txt"
    cat "$outfile" | gf or | sed 's/=.*/=/'

    for file in "$xss_file" "$or_file" "$lfi_file" "$sqli_file"; do
        [[ ! -s "$file" ]] && rm "$file" 2>/dev/null
    done

    echo -ne "\n\n${yellowColour}[!]${grayColour} Filtered URLs have been saved to the respective output files in '$output_dir':\n"

    if [[ -s "$xss_file" || -s "$or_file" || -s "$lfi_file" || -s "$sqli_file" ]]; then
        [[ -s "$xss_file" ]] && echo -ne "\n${greenColour}[+]${grayColour}  XSS: $xss_file"
        [[ -s "$or_file" ]] && echo -ne "\n${greenColour}[+]${grayColour}  Open Redirect: $or_file"
        [[ -s "$lfi_file" ]] && echo -ne "\n${greenColour}[+]${grayColour}  LFI: $lfi_file"
        [[ -s "$sqli_file" ]] && echo -ne "\n${greenColour}[+]${grayColour}  SQLi: $sqli_file"
    else
        echo -ne "\n${redColour}[!]${grayColour} No filtered URLs found. No vulnerabilities detected."
    fi

    echo -ne "\n\n${blueColour}[+]${grayColour} Press Enter to continue" && read
    tput cnorm
}

# Function to run vulnerability scanning
run_vuln_scan() {
    clear; echo -ne "${purpleColour}[?]${grayColour} Enter the website URL or domain: "
    read website_input
    output_dir="output_${website_input}"
    mkdir -p "$output_dir"
    [[ ! $website_input =~ ^https?:// ]] && website_url="https://$website_input" || website_url="$website_input"
    clear; tput civis
    echo -ne "${blueColour}[!]${grayColour} Normalized URL being used: $website_url"

    echo -e "\n\n${blueColour}[*]${grayColour} Running katana with passive sources (waybackarchive, commoncrawl, alienvault)..."
    echo "$website_url" | katana -ps -pss waybackarchive,commoncrawl,alienvault -f qurl | uro > "$output_dir/output.txt"

    echo -e "${blueColour}[*]${grayColour} Running katana actively with depth 5..."
    katana -u "$website_url" -d 5 -f qurl | uro | anew "$output_dir/output.txt"

    katana_file="$output_dir/output.txt"

    if [[ ! -s "$katana_file" ]]; then
        sudo rm "$katana_file"
        echo -e "\n${redColour}[!]${grayColour} No URLs were collected. Exiting..."
        sleep 3; menu
    fi

    # SQLi
    gfpinstall
    echo -e "\n${greenColour}[!]${grayColour} Filtering URLs for potential SQLi endpoints...\n"; sleep 1
    sqli_file="$output_dir/sqli_output.txt"
    cat "$output_dir/output.txt" | gf sqli | sed 's/=.*/=/' 

    # XSS
    echo -e "\n${greenColour}[!]${grayColour} Filtering URLs for potential XSS endpoints...\n"; sleep 1
    xss_file="$output_dir/xss_output.txt"
    cat "$output_dir/output.txt" | Gxss | kxss | grep -oP '^URL: \K\S+' | sed 's/=.*/=/'
    
    # LFI
    echo -e "\n${greenColour}[!]${grayColour} Filtering URLs for potential LFI endpoints...\n"; sleep 1
    lfi_file="$output_dir/lfi_output.txt"
    cat "$output_dir/output.txt" | gf lfi | sed 's/=.*/=/'

    # Open Redirect
    echo -e "\n${greenColour}[!]${grayColour} Filtering URLs for potential OR endpoints...\n"; sleep 1
    or_file="$output_dir/open_redirect_output.txt"
    cat "$output_dir/output.txt" | gf or | sed 's/=.*/=/'

    for file in "$xss_file" "$or_file" "$lfi_file" "$sqli_file"; do
        [[ ! -s "$file" ]] && rm "$file" 2>/dev/null
    done

    echo -ne "\n\n${yellowColour}[!]${grayColour} Filtered URLs have been saved to the respective output files in '$output_dir':\n"

    if [[ -s "$xss_file" || -s "$or_file" || -s "$lfi_file" || -s "$sqli_file" ]]; then
        [[ -s "$xss_file" ]] && echo -ne "\n${greenColour}[+]${grayColour}  XSS: $xss_file"
        [[ -s "$or_file" ]] && echo -ne "\n${greenColour}[+]${grayColour}  Open Redirect: $or_file"
        [[ -s "$lfi_file" ]] && echo -ne "\n${greenColour}[+]${grayColour}  LFI: $lfi_file"
        [[ -s "$sqli_file" ]] && echo -ne "\n${greenColour}[+]${grayColour}  SQLi: $sqli_file"
    else
        echo -ne "\n${redColour}[!]${grayColour} No filtered URLs found. No vulnerabilities detected."
    fi

    echo -ne "\n\n${blueColour}[+]${grayColour} Press Enter to continue" && read
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
    cat "$subdir/subdomains.txt" | httpx-toolkit -ports 80,443,8080,8000,8888 -threads 200 > "$subdir/active_subdomains.txt"

    echo -e "\n${redColour}[!]${grayColour} Subdomain results for ${domainsub}:"

    if [[ -s "$subdir/subdomains.txt" ]]; then
        echo -ne "\n${blueColour}[+]${grayColour}${yellowColour} All${grayColour} subdomains: $subdir/subdomains.txt"
    else
        echo -ne "\n${redColour}[!]${grayColour} No subdomains found."
    fi

    if [[ -s "$subdir/active_subdomains.txt" ]]; then
        echo -ne "\n${blueColour}[+]${grayColour}${greenColour} Active${grayColour} subdomains: $subdir/active_subdomains.txt"
    else
        echo -ne "\n${redColour}[!]${grayColour} No active subdomains found."
        sudo rm -rf $subdir
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
    echo -e "\n${greenColour}[+]${grayColour} Version 1.4"
    echo -e "${greenColour}[+]${grayColour} Github: https://github.com/Kidd3n"
    echo -e "${greenColour}[+]${grayColour} Discord ID: kidd3n.sh"
    echo -ne "\n${greenColour}[+]${grayColour} Press Enter to continue" && read
    clear
    programs
    while true; do
        menu
    done
fi