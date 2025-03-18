#!/bin/bash

# =============================================
# Configuración inicial y colores
# =============================================
greenColour="\e[0;32m\033[1m"
endColour="\033[0m\e[0m"
redColour="\e[0;31m\033[1m"
blueColour="\e[0;34m\033[1m"
yellowColour="\e[0;33m\033[1m"
purpleColour="\e[0;35m\033[1m"
turquoiseColour="\e[0;36m\033[1m"
grayColour="\e[0;37m\033[1m"

trap ctrl_c INT
pathmain=$(pwd)

# =============================================
# Funciones base y manejo de errores
# =============================================
ctrl_c() {
    echo -e "\n\n${redColour}[!]${endColour}${grayColour} Exit...${endColour}\n"
    sudo rm -rf output_* subdomains_* 2>/dev/null
    tput cnorm
    exit 1
}

error_exit() {
    echo -e "\n${redColour}[!] ERROR: $1${endColour}"
    echo -e "${blueColour}[*] Solución: $2${endColour}\n"
    exit 1
}

validate_dependency() {
    if ! command -v $1 &>/dev/null; then
        error_exit "Falta la dependencia crítica: $1" \
        "Instálela manualmente con: $2"
    fi
}

validate_domain() {
    [[ ! "$1" =~ ^([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$ ]] && 
        error_exit "Dominio inválido: $1" "Use formato: ejemplo.com"
}

# =============================================
# Soporte Multiplataforma
# =============================================
detect_os() {
    source /etc/os-release 2>/dev/null
    case $ID in
        "debian"|"ubuntu"|"kali"|"linuxmint") PKG_MGR="apt -y" ;;
        "centos"|"fedora") PKG_MGR="yum -y" ;;
        "arch")            PKG_MGR="pacman -S --noconfirm" ;;
        *)                 error_exit "Sistema no soportado: $ID" "Use Debian/Ubuntu/CentOS/Arch" ;;
    esac
}

install_package() {
    echo -e "${blueColour}[*] Instalando $1...${endColour}"
    sudo $PKG_MGR install $1 >/dev/null 2>&1 || 
        error_exit "Fallo instalando $1" "1. Actualice repos 2. Ejecute manualmente: sudo $PKG_MGR install $1"
}

# =============================================
# Actualización Automática (--update)
# =============================================
update_tools() {
    echo -e "\n${greenColour}[*] Actualizando herramientas...${endColour}"
    
    declare -A tool_repos=(
        ["katana"]="projectdiscovery/katana"
        ["Gxss"]="KathanP19/Gxss"
        ["kxss"]="Emoe/kxss"
        ["gf"]="tomnomnom/gf"
        ["anew"]="tomnomnom/anew"
        ["httpx"]="projectdiscovery/httpx"
        ["subfinder"]="projectdiscovery/subfinder"
        ["nuclei"]="projectdiscovery/nuclei"
        ["subzy"]="PentestPad/subzy"
    )

    for tool in "${!tool_repos[@]}"; do
        echo -e "${blueColour}[*] Actualizando $tool...${endColour}"
        go install "github.com/${tool_repos[$tool]}@latest" 2>/dev/null || 
            echo -e "${redColour}[!] Error actualizando $tool${endColour}"
    done
    
    echo -e "${blueColour}[*] Actualizando GF patterns...${endColour}"
    [ -d ~/.gf ] && git -C ~/.gf pull >/dev/null 2>&1
    
    echo -e "${greenColour}[+] Actualización completada!${endColour}"
    exit 0
}

# =============================================
# Paralelización de Tareas
# =============================================
install_parallel() {
    if ! command -v parallel &>/dev/null; then
        echo -e "${yellowColour}[!] GNU parallel no encontrado, instalando...${endColour}"
        install_package "parallel"
    fi
}

run_parallel() {
    install_parallel
    parallel -j $1 "$2"
}

# =============================================
# Instalación de Dependencias
# =============================================
programs() {
    echo -e "\n${blueColour}[*] Verificando dependencias...${endColour}"
    
    # Instalar paquetes base
    base_packages=(curl git golang-go pipx)
    for pkg in "${base_packages[@]}"; do
        if ! command -v $pkg &>/dev/null; then
            install_package "$pkg"
        fi
    done

    # Instalar GNU Parallel
    install_parallel

    # Instalar herramientas Go
    declare -A install_commands=(
        ["katana"]="go install github.com/projectdiscovery/katana/cmd/katana@latest"
        ["uro"]="pipx install uro --force"
        ["Gxss"]="go install github.com/KathanP19/Gxss@latest"
        ["kxss"]="go install github.com/Emoe/kxss@latest"
        ["gf"]="go install github.com/tomnomnom/gf@latest"
        ["anew"]="go install github.com/tomnomnom/anew@latest"
        ["httpx"]="go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"
        ["subfinder"]="go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        ["httpx-toolkit"]="install_package httpx-toolkit"
        ["nuclei"]="go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
        ["subzy"]="go install -v github.com/PentestPad/subzy@latest"
    )

    for tool in "${!install_commands[@]}"; do
        if ! command -v $tool &>/dev/null; then
            echo -e "${blueColour}[*] Instalando $tool...${endColour}"
            eval "${install_commands[$tool]}" >/dev/null 2>&1
            [ -f $HOME/go/bin/$tool ] && sudo cp $HOME/go/bin/$tool /usr/local/bin/
        fi
    done

    # Configurar GF patterns
    if ! ls ~/.gf/*.json &>/dev/null; then
        echo -e "${blueColour}[*] Instalando GF patterns...${endColour}"
        git clone https://github.com/coffinxp/GFpattren.git /tmp/GFpattern >/dev/null 2>&1
        mkdir -p ~/.gf && cp /tmp/GFpattern/*.json ~/.gf/
        rm -rf /tmp/GFpattern
    fi

    echo -e "\n${greenColour}[+] Dependencias verificadas!${endColour}"
    sleep 2
    clear
}

# =============================================
# Funciones principales de escaneo
# =============================================
fetch_wayback_urls() {
    clear
    echo -ne "${purpleColour}[?] Dominio (ej. example.com): ${endColour}"
    read domain
    validate_domain "$domain"
    
    output_dir="output_${domain}"
    mkdir -p "$output_dir"
    
    echo -e "\n${blueColour}[*] Obteniendo URLs históricas...${endColour}"
    curl -s "https://web.archive.org/cdx/search/cdx?url=*.$domain/*&collapse=urlkey&output=text&fl=original" \
        -o "$output_dir/all_urls.txt"
    
    echo -e "\n${blueColour}[*] Filtrando URLs con extensiones...${endColour}"
    curl -s "https://web.archive.org/cdx/search/cdx?url=*.$domain/*&collapse=urlkey&output=text&fl=original&filter=original:.*\\.(xls|xml|xlsx|json|pdf|sql|doc|docx|pptx|txt|git|zip|tar\\.gz|tgz|bak|7z|rar|log|cache|secret|db|backup|yml|gz|config|csv|yaml|md|md5|exe|dll|bin|ini|bat|sh|tar|deb|rpm|iso|img|env|apk|msi|dmg|tmp|crt|pem|key|pub|asc)$" \
        -o "$output_dir/filtered_urls.txt"
    
    echo -e "\n${greenColour}[+] Resultados guardados en:${endColour}"
    ls -1 $output_dir/*.txt 2>/dev/null || echo -e "${redColour}[!] No se encontraron resultados${endColour}"
    read -p "Presione Enter para continuar..."
}

run_vuln_scan() {
    clear
    echo -ne "${purpleColour}[?] URL/Dominio a escanear: ${endColour}"
    read website_input
    validate_domain "$(echo "$website_input" | awk -F/ '{print $3}')"
    
    output_dir="output_${website_input}"
    mkdir -p "$output_dir"
    website_url="$( [[ $website_input =~ ^https?:// ]] && echo "$website_input" || echo "https://$website_input" )"
    
    echo -e "\n${blueColour}[*] Escaneando con Katana...${endColour}"
    echo "$website_url" | katana -ps -pss waybackarchive,commoncrawl,alienvault -f qurl | uro > "$output_dir/katana_output.txt"
    
    echo -e "\n${blueColour}[*] Buscando vulnerabilidades...${endColour}"
    declare -A vuln_checks=(
        ["SQLi"]="gf sqli | sed 's/=.*/=/'"
        ["XSS"]="Gxss | kxss | grep -oP '^URL: \K\S+' | sed 's/=.*/=/'"
        ["LFI"]="gf lfi | sed 's/=.*/=/'"
        ["Open Redirect"]="gf redirect | sed 's/=.*/=/'"
    )
    
    for vuln in "${!vuln_checks[@]}"; do
        echo -e "\n${yellowColour}[*] Buscando $vuln...${endColour}"
        cat "$output_dir/katana_output.txt" | eval "${vuln_checks[$vuln]}" > "$output_dir/${vuln// /_}.txt"
    done
    
    echo -e "\n${greenColour}[+] Resultados:${endColour}"
    ls -1 $output_dir/*.txt 2>/dev/null || echo -e "${redColour}[!] No se encontraron vulnerabilidades${endColour}"
    read -p "Presione Enter para continuar..."
}

subfinderfun() {
    clear
    echo -ne "${purpleColour}[?] Dominio para subdominios (ej. example.com): ${endColour}"
    read domain
    validate_domain "$domain"
    
    output_dir="subdomains_${domain}"
    mkdir -p "$output_dir"
    
    echo -e "\n${blueColour}[*] Buscando subdominios...${endColour}"
    subfinder -d "$domain" -all -recursive -silent > "$output_dir/all_subdomains.txt"
    
    echo -e "\n${blueColour}[*] Verificando subdominios activos...${endColour}"
    run_parallel 100 "httpx -silent -status-code" < "$output_dir/all_subdomains.txt" > "$output_dir/active_subdomains.txt"
    
    echo -e "\n${greenColour}[+] Resultados guardados en:${endColour}"
    ls -1 $output_dir/*.txt
    read -p "Presione Enter para continuar..."
}

takeoversubfun() {
    clear
    echo -ne "${purpleColour}[?] Ruta de subdominios activos: ${endColour}"
    read sub_file
    [ ! -f "$sub_file" ] && error_exit "Archivo no encontrado" "Verifique la ruta"
    
    echo -e "\n${blueColour}[*] Verificando takeovers...${endColour}"
    subzy run --targets "$sub_file" --concurrency 50 --hide_fails
    
    read -p "Presione Enter para continuar..."
}

# =============================================
# Nuclei AI Function
# =============================================
nucleiai() {
    tput cnorm
    nuclei -auth
    
    main_ai() {
        tput cnorm
        echo -ne "\n${yellowColour}[?]${grayColour} Archivo de URLs: "
        read urlfile
        
        while [[ ! -f "$urlfile" ]]; do
            echo -e "${redColour}[!]${grayColour} Archivo no encontrado!"
            echo -ne "${yellowColour}[?]${grayColour} Archivo de URLs: "
            read urlfile
        done
        
        echo -ne "${blueColour}[?]${grayColour} Prompt para Nuclei AI: "
        read prompt
        
        nuclei -l "$urlfile" -ai "$prompt"
        main_ai
    }
    
    main_ai
}

# =============================================
# Banner Inicial
# =============================================
show_banner() {
    tput civis
    clear
    echo -ne "${redColour}"
    echo -ne "                    _            \n"
    echo -ne "  /\\  /\\_   _ _ __ | |_ ___ _ __ \n"
    echo -ne " / /_/ / | | | '_ \\| __/ _ \\ '__|\n"
    echo -ne "/ __  /| |_| | | | | ||  __/ |   \n"
    echo -ne "\\/ /_/  \\__,_|_| |_|\\__\\___|_|   \n"
    echo -e "\n${greenColour}[+]${grayColour} Versión 1.3"
    echo -e "${greenColour}[+]${grayColour} Github: https://github.com/Kidd3n"
    echo -e "${greenColour}[+]${grayColour} Discord ID: kidd3n.sh"
    echo -ne "\n${greenColour}[+]${grayColour} Presione Enter para continuar${endColour}" && read
    clear
}

# =============================================
# Menú Principal
# =============================================
menu() {
    while true; do
        clear
        echo -e "${greenColour}"
        echo "                    _            "
        echo "  /\\  /\\_   _ _ __ | |_ ___ _ __ "
        echo " / /_/ / | | | '_ \\| __/ _ \\ '__|"
        echo "/ __  /| |_| | | | | ||  __/ |   "
        echo "\\/ /_/  \\__,_|_| |_|\\__\\___|_|   "
        echo -e "\n${yellowColour}[1]${grayColour} Escanear endpoints (XSS, SQLi, LFI)"
        echo -e "${yellowColour}[2]${grayColour} Buscar subdominios"
        echo -e "${yellowColour}[3]${grayColour} Obtener URLs históricas"
        echo -e "${yellowColour}[4]${grayColour} Verificar takeovers"
        echo -e "${yellowColour}[5]${grayColour} Shell Nuclei AI"
        echo -e "\n${redColour}[99]${grayColour} Salir${endColour}"
        
        read -p "Seleccione opción: " option
        
        case $option in
            1) run_vuln_scan ;;
            2) subfinderfun ;;
            3) fetch_wayback_urls ;;
            4) takeoversubfun ;;
            5) nucleiai ;;
            99) ctrl_c ;;
            *) echo -e "${redColour}Opción inválida!${endColour}"; sleep 1 ;;
        esac
    done
}

# =============================================
# Ejecución Principal
# =============================================
if [[ $(id -u) -ne 0 ]]; then
    error_exit "Debe ejecutarse como root" "sudo $0"
fi

detect_os
[[ "$1" == "--update" ]] && update_tools
show_banner
programs
menu