echo -e "${BLUE}[*] Sudo instalado${RESET}"
if dpkg-query -s sudo &>/dev/null; then
    echo -e "${GREEN}[+] Sudo instalado\n"
    counter=$((counter + 1))
else
    echo -e "${PINK}[-] Sudo no instalado"
    echo "[SOFTWARE] SUDO: SUDO no instalado" >> "$LOG_FILE"
fi


echo -e "${BLUE}[*] Los comandos sudo utilizan pty${RESET}"
output1=$(grep -rPi -- '^\h*Defaults\h+([^#\n\r]+,\h*)?use_pty\b' /etc/sudoers*)
output2=$(grep -rPi -- '^\h*Defaults\h+([^#\n\r]+,\h*)?!use_pty\b' /etc/sudoers*)
exit_code2=$?
if [[ $output1 == *"use_pty"* && $exit_code2 -ne 0 ]]; then
    echo -e "${GREEN}[+] $output1"
    counter=$((counter + 1))
else
    echo -e "${PINK}[-] $output1 $output2"
    echo "[CONFIG] SUDO: PTY mal configurado" >> "$LOG_FILE"
fi

echo -e "\n"

echo -e "${BLUE}[*] El archivo de registro sudo${RESET}"
output=$(grep -rPsi "^\h*Defaults\h+([^#]+,\h*)?logfile\h*=\h*(\"|\')?\H+(\"|\')?(,\h*\H+\h*)*\h*(#.*)?$" /etc/sudoers*)
if [[ $output == *"logfile"* ]]; then
        echo -e "${GREEN}[+] $output"
        counter=$((counter + 1))
else
        echo -e "${PINK}[-] El archivo log de sudo no existe"
        echo -e "${YELLOW}[!] Para corregir:"
        echo -e "Editar el archivo sudoers -> sudo visudo"
        echo -e 'Añadir esta linea:\nDefaults\tlogfile="/var/log/sudo.log"'
        echo "[CONFIG] SUDO: Archivo sudo.log no existe" >> "$LOG_FILE"
fi

echo -e "\n"

echo -e "${BLUE}[*] Garantizar que los usuarios deban proporcionar una contraseña para la elevación de privilegios${RESET}"
output=$(grep -r "^[^#].*NOPASSWD" /etc/sudoers*)
exit_code=$?
if [[ $exit_code -eq 0 ]]; then
        echo -e "${PINK}[-] No todos los usuarios proporcionan clave\n -> $output"
        echo "[PRIVILEGE] USER: No todos los usuarios proporcionan clave" >> "$LOG_FILE"
else
        echo -e "${GREEN}[+] Todos los usuarios proporcionan clave"
        counter=$((counter + 1))
fi

echo -e "\n"

echo -e "${BLUE}[*] La reautenticación para la escalada de privilegios no está desactivada globalmente${RESET}"
output=$(grep -r "^[^#].*\!authenticate" /etc/sudoers*)
exit_code=$?
if [[ $exit_code -eq 1 ]]; then
        echo -e "${GREEN}[+] La reautenticacion de privilegios no esta desactivada globalmente"
        counter=$((counter + 1))
else
        echo -e "${PINK}[-] La reautenticacion de privilegios esta desactivada globalmente\n$output"
        echo "[PRIVILEGE] REAUTENTICACION: Desactivada globalmente" >> "$LOG_FILE"
fi

echo -e "\n"

echo -e "${BLUE}[*] Tiempo de espera de autenticación sudo configurado correctamente${RESET}"
output=$(grep -roP "timestamp_timeout=\K[0-9]*" /etc/sudoers*)
if [[ -n $output ]]; then
        echo -e "${GREEN}[+] TimeStamp configurado:\n$output\nEl valor no tiene que ser tan alto"
        counter=$((counter + 1))
else
        output=$(sudo -V | grep -i "Authentication timestamp timeout:")
        if [[ -n $output ]]; then
                echo -e "${PINK}[!] No TimeSttamp configurado. Por defecto es 15 minutos"
                echo -e "${YELLOW}[!] Para corregir:"
                echo -e "Editar el archivo sudoers -> sudo visudo"
                echo -e 'Añadir estas lineas:\nDefaults\tenv_reset, timestamp_timeout=15'
                echo -e 'Defaults\ttimestamp_timeout=15'
                echo -e 'Defaults\tenv_reset'
                echo "[PRIVILEGE] SUDO: Tiempo de autenticacion sudo no configurado" >> "$LOG_FILE"
        else
                echo -e "${GREEN}[+] TimeSttamp configurado:\n$output\n. Por defecto es 15 minutos"
                counter=$((counter + 1))
        fi
fi

echo -e "\n"

echo -e "${BLUE}[*] Asegurarse de que el acceso al comando su está restringido${RESET}"
# Verificar si pam_wheel.so está configurado
config=$(grep -E '^\s*auth\s+required\s+pam_wheel\.so' /etc/pam.d/su)

# Verificar el grupo configurado (por defecto, wheel)
group=$(echo "$config" | grep -oP 'group=\K\w+')

if [[ -z "$config" ]]; then
    echo -e "${RED}[-] La configuración de su no está restringida (pam_wheel.so no configurado)${RESET}"
    echo "[PRIVILEGE] SU: comando su no restringido" >> "$LOG_FILE"
elif [[ -z "$group" ]]; then
    echo -e "${PINK}[-] pam_wheel.so configurado, pero no se especificó ningún grupo${RESET}"
    echo "[PRIVILEGE] SU: pam_wheel sin grupo especifico" >> "$LOG_FILE"
else
    # Verificar si el grupo está vacío
    users=$(grep "^$group:" /etc/group | cut -d: -f4)
    if [[ -z "$users" ]]; then
        echo -e "${GREEN}[+] Configuración correcta: su está restringido al grupo '$group' y el grupo está vacío${RESET}"
        counter=$((counter + 1))
    else
        echo -e "${PINK}[-] El grupo '$group' tiene usuarios: $users${RESET}"
        echo "[PRIVILEGE] SU: el $group no esta vacio" >> "$LOG_FILE"
    fi
fi

