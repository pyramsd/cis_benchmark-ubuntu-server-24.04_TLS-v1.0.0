#!/usr/bin/env bash

# ====== Configuración ======
SCRIPT_DIR="$(dirname "$(realpath "$0")")"
LOG_FILE="$SCRIPT_DIR/logs/errors.log"

# ====== Verificación de existencia ======
if [[ ! -f "$LOG_FILE" ]]; then
    echo "Error: No se encontró el archivo: $LOG_FILE" >&2
    exit 1
fi

# ====== Cargar líneas útiles ======
mapfile -t lineas < <(grep -vE '^\s*(#|$)' "$LOG_FILE")

if (( ${#lineas[@]} == 0 )); then
    echo "El archivo existe pero no tiene contenido útil."
    exit 0
fi

# ====== Agrupar por tipo ======
declare -A grupos
for linea in "${lineas[@]}"; do
    if [[ "$linea" =~ ^\[([A-Z_]+)\]\ (.*) ]]; then
        tipo="${BASH_REMATCH[1]}"
        contenido="${BASH_REMATCH[2]}"
        grupos["$tipo"]+="${contenido}"$'\n'
    fi
done

# ====== Nombres legibles ======
declare -A nombres_legibles=(
    ["FILE_PERMISSION"]="Permisos de archivos"
    ["FIREWALL"]="Firewall"
    ["SOFTWARE"]="Software"
    ["CONFIG"]="Configuración"
    ["PRIVILEGE"]="Escalado de privilegios"
    ["ROOT_ACCOUNT"]="Cuenta root"
    ["GROUP"]="Grupos de usuario"
    ["CIPHERS"]="Cifrados SSH"
    ["DUPLICATE_GROUPS"]="Grupos duplicados"
    ["DUPLICATE_GUIDs"]="GIDs duplicados"
    ["DUPLICATE_NAMES"]="Nombres de usuario duplicados"
    ["DUPLICATE_UIDs"]="UIDs duplicados"
    ["FILE"]="Archivos del sistema"
    ["GROUP_SHADOW"]="Grupo Shadow"
    ["MTA_CONFIG"]="Configuración MTA"
    ["PASSWD"]="Fichero Passwd"
    ["SHADOW"]="Fichero Shadow"
)

# ====== Funciones de solución ======
mostrar_solucion() {
    local tipo="$1" subtipo="$2" contenido="${3:-}"

    echo
    echo -e "${YELLOW}Solución recomendada para $tipo → $subtipo:"

    case "$tipo:$subtipo" in
        ("FILE_PERMISSION:Cron")
            echo -e "1. Identificar el archivo con permisos incorrectos."
            if [[ -n "$contenido" ]]; then
                echo "$contenido" | grep "Cron:" | while read -r linea; do
                    archivo=$(echo "$linea" | grep -oE '/etc/[^ ]+')
                    [[ -z "$archivo" ]] && continue
                    echo -e "   - $archivo"
                done
            fi
            echo -e "\n2. Cambiar los permisos del archivo."
            echo "$contenido" | grep "Cron:" | while read -r linea; do
                archivo=$(echo "$linea" | grep -oE '/etc/[^ ]+')
                [[ -z "$archivo" ]] && continue

                case "$archivo" in
                    (/etc/crontab)
                        echo -e "   -> chmod 600 "$archivo""
                        ;;
                    (*)
                        echo -e "   -> chmod 700 "$archivo""
                        ;;
                esac
                echo -e "      chown root:root "$archivo""
            done
            ;;
        ("FILE_PERMISSION:SSH")
            echo -e "1. Identificar el archivo con permisos incorrectos."
            if [[ -n "$contenido" ]]; then
                echo "$contenido" | grep "SSH:" | while read -r linea; do
                    archivo=$(echo "$linea" | grep -oE '/etc/ssh/[^ ]+')
                    [[ -z "$archivo" ]] && continue
                    echo -e "   - $archivo"
                done
            fi
            echo -e "\n2. Cambiar los permisos del archivo."
            echo "$contenido" | grep "SSH:" | while read -r linea; do
                archivo=$(echo "$linea" | grep -oE '/etc/ssh/[^ ]+')
                [[ -z "$archivo" ]] && continue

                case "$archivo" in
                    (*)
                        echo -e "   -> chmod 600 "$archivo""
                        ;;
                esac
                echo -e "      chown root:root "$archivo""
            done
            ;;
        ("SOFTWARE" | "SOFTWARE:")
            echo -e "1. Crea un archivo que contenga programas permitidos en tu sistema."
            echo -e "   -> vim whitelist.txt\n"
            echo -e "2. Agregar programas a la lista\n   ftp\n   rync\n   telnet\n"
            echo -e "3. Ejecute el script:\n   -> sudo cis-audit.sh --allowded-programs=whitelist.txt${RESET}"
            ;;
        ("CONFIG:SUDO")
            sudo_log_file="/var/log/sudo.log"
            if [[ ! -f "$sudo_log_file" ]]; then
                echo -e "\n- Añadir el archivo: $sudo_log_file" >&2
                echo -e "echo \"Defaults        logfile=\"/var/log/sudo.log\"\" >> /etc/sudoers${RESET}" 
            fi
            ;;
        ("CONFIG:SSH")
            echo -e "1. Edite el fichero /etc/ssh/sshd_config"
            echo -e "2. Asegurese de que los siguientes valores esten configurados:"

            if [[ "$contenido" =~ "logingracetime" ]]; then
                echo -e "   - LoginGraceTime 60"
            fi
            if [[ "$contenido" =~ "maxauthtries" ]]; then
                echo -e "   - MaxAuthTries 4"
            fi
            if [[ "$contenido" =~ "PermitRootLogin" ]]; then
                echo -e "   - PermitRootLogin no"
            fi
            if [[ "$contenido" =~ "disableforwarding" ]]; then
                echo -e "   - DisableForwarding yes"
            fi
            if [[ "$contenido" =~ "gssapiauthentication" ]]; then
                echo -e "   - GSSAPIAuthentication no"
            fi
            if [[ "$contenido" =~ "hostbasedauthentication" ]]; then
                echo -e "   - HostbasedAuthentication no"
            fi
            if [[ "$contenido" =~ "ignorerhosts" ]]; then
                echo -e "   - IgnoreRhosts yes"
            fi
            if [[ "$contenido" =~ "loglevel" ]]; then
                echo -e "   - LogLevel INFO"
            fi
            if [[ "$contenido" =~ "permitemptypasswords" ]]; then
                echo -e "   - PermitEmptyPasswords no"
            fi
            if [[ "$contenido" =~ "permituserenvironment" ]]; then
                echo -e "   - PermitUserEnvironment no"
            fi
            if [[ "$contenido" =~ "maxstartups" ]]; then
                echo -e "   - MaxStartups 10:30:60"
            fi
            if [[ "$contenido" =~ "clientaliveinterval" ]]; then
                echo -e "   - ClientAliveInterval <valor numerico>"
            fi
            if [[ "$contenido" =~ "clientalivecountmax" ]]; then
                echo -e "   - ClientAliveCountMax <valor numerico>"
            fi
            if [[ "$contenido" =~ "kexalgorithms" ]]; then
                echo -e "   - KexAlgorithms <lista de algoritmos seguros>"
            fi
            if [[ "$contenido" =~ "macs" ]]; then
                echo -e "   - MACs <lista de MACs seguros>"
            fi
            if [[ "$contenido" =~ "usepam" ]]; then
                echo -e "   - UsePAM yes"
            fi
            if [[ "$contenido" =~ "accesos no configurados" ]]; then
                echo -e "   - AllowUsers <lista de usuarios>"
                echo -e "   - AllowGroups <lista de grupos>"
                echo -e "   - DenyUsers <lista de usuarios>"
                echo -e "   - DenyGroups <lista de grupos>"
            fi
            ;;
        ("CIPHERS:SSH")
            echo -e "Revisar la configuración de cifrados en /etc/ssh/sshd_config. Se recomiendan algoritmos modernos y seguros."
            echo -e "Evitar el uso de cifrados débiles o desactualizados como los basados en CBC."
            ;;
        ("DUPLICATE_GROUPS")
            echo -e "Existen nombres de grupo duplicados en /etc/group. Cada nombre de grupo debe ser único."
            echo -e "Use 'awk -F: '(\$1 duplicates[\$1]++) {print \$1}' /etc/group' para encontrarlos y edítelos manualmente."
            ;;
        ("DUPLICATE_GUIDs")
            echo -e "Existen GIDs (Group IDs) duplicados en /etc/group. Cada GID debe ser único."
            echo -e "Use 'awk -F: '(\$3 duplicates[\$3]++) {print \$3}' /etc/group' para encontrarlos y 'groupmod -g <new_gid> <group_name>' para corregirlos."
            ;;
        ("DUPLICATE_NAMES")
            echo -e "Existen nombres de usuario duplicados en /etc/passwd. Cada nombre debe ser único."
            echo -e "Use 'awk -F: '(\$1 duplicates[\$1]++) {print \$1}' /etc/passwd' para encontrarlos y 'usermod -l <new_name> <old_name>' para renombrar."
            ;;
        ("DUPLICATE_UIDs")
            echo -e "Existen UIDs (User IDs) duplicados en /etc/passwd. Cada UID debe ser único."
            echo -e "Use 'awk -F: '(\$3 duplicates[\$3]++) {print \$3}' /etc/passwd' para encontrarlos y 'usermod -u <new_uid> <user_name>' para corregirlos."
            ;;
        ("FILE:File_System")
            echo -e "Faltan archivos importantes del sistema. Revise el log para ver cuáles son y reinstale el paquete correspondiente."
            ;;
        ("FILE_PERMISSION:File_System")
            echo -e "Se han detectado permisos incorrectos en archivos/directorios del sistema. Revise el log para detalles."
            echo -e "Use 'chmod' y 'chown' para restaurar los permisos recomendados."
            ;;
        ("GROUP")
            echo -e "Se han detectado usuarios en /etc/passwd que pertenecen a un GID que no existe en /etc/group."
            echo -e "Identifique los usuarios y asígneles un grupo válido editando /etc/passwd."
            ;;
        ("GROUP_SHADOW")
            echo -e "El grupo 'shadow' no debería tener miembros. Remueva cualquier usuario de este grupo editando /etc/group."
            ;;
        ("MTA_CONFIG")
            echo -e "La configuración del Mail Transfer Agent (MTA) no es segura."
            echo -e "Asegúrese de que el MTA esté configurado para escuchar solo en la interfaz de localhost (127.0.0.1)."
            ;;
        ("PASSWD")
            echo -e "Se han encontrado cuentas en /etc/passwd que no usan contraseñas ocultas (shadowed passwords)."
            echo -e "Use el comando 'pwconv' para migrar las contraseñas a /etc/shadow."
            ;;
        ("PRIVILEGE:REAUTENTICACION")
            echo -e "La reautenticación para sudo está desactivada globalmente ('!authenticate')."
            echo -e "Elimine la directiva '!authenticate' del fichero /etc/sudoers (usando 'visudo')."
            ;;
        ("PRIVILEGE:SU")
            echo -e "El acceso al comando 'su' no está restringido."
            echo -e "Se recomienda restringir 'su' a un grupo (ej. 'wheel') usando 'pam_wheel.so' en /etc/pam.d/su."
            ;;
        ("PRIVILEGE:SUDO")
            echo -e "Tiempo de espera de autenticación sudo configurado incorrectamente o no configurado."
            echo -e "Revisar las directivas en /etc/sudoers (con 'visudo')"
            echo -e "Ejmemplo:\ncomando: sudo visudo\nAñadir:\nDefaults    env_reset, timestamp_timeout=15 o <15"
            ;;
        ("PRIVILEGE:USER")
            echo -e "Se han detectado usuarios con la directiva 'NOPASSWD' en la configuración de sudo."
            echo -e "Elimine la etiqueta 'NOPASSWD' de las reglas de sudo para requerir siempre una contraseña."
            ;;
        ("ROOT_ACCOUNT:PATH")
            echo -e "La variable de entorno PATH del usuario root es insegura."
            echo -e "Corrija el PATH en los archivos de inicio de root (ej. .bashrc, .profile) para eliminar directorios como '.'."
            ;;
        ("ROOT_ACCOUNT:ROOT")
            echo -e "La configuración de la cuenta root (UID/GID) es incorrecta. El UID y GID de root deben ser 0 y únicos."
            echo -e "Revise /etc/passwd y /etc/group."
            ;;
        ("ROOT_ACCOUNT:UMASK")
            echo -e "El 'umask' por defecto para el usuario root no es seguro (debería ser 027 o más restrictivo)."
            echo -e "Configure el 'umask' en los archivos de inicio de root como /etc/profile o /root/.bashrc."
            ;;
        ("SHADOW" | "SHADOW:")
            echo -e "Se han detectado cuentas en /etc/shadow sin contraseña."
            echo -e "Use 'passwd <user>' para asignar una contraseña o 'passwd -l <user>' para bloquear la cuenta."
            ;;
        (*)
            echo -e "No hay una solución específica registrada para este subtipo."
            ;;
    esac

    echo -e ${RESET}

    read -p "¿Desea aplicar la solución? (s/N): " resp
    if [[ "$resp" =~ ^[sSyY]$ ]]; then
        echo -e "${GREEN}Aplicando solución...\n${RESET}"
        aplicar_solucion "$tipo" "$subtipo"
        read -p "Presione Enter para continuar..."
    else
        echo -e "${BLUE}Volviendo al menú principal...${RESET}"
        sleep 1
    fi
}

aplicar_solucion() {
    local tipo="$1" subtipo="$2"
    case "$tipo:$subtipo" in
        "SOFTWARE" | "SOFTWARE:")
            echo "Creando archivo whitelist.txt..."
            touch whitelist.txt
            echo -e "Archivo whitelist.txt creado."
            echo -e "Ahora ejecute:\n-> sudo cis-audit --allowded-programs=whitelist.txt\n"
            ;;
        "CONFIG:SUDO")
            sudo_log_file="/var/log/sudo.log"
            if [[ ! -f "$sudo_log_file" ]]; then
                echo "Defaults        logfile=\"/var/log/sudo.log\"" >> /etc/sudoers 
            fi
            ;;
        "PRIVILEGE:SUDO")
            echo "Abriendo /etc/sudoers con visudo..."
            visudo
            echo "Edición completada."
            ;;
        *)
            echo "Sin acción específica para este tipo/subtipo."
            ;;
    esac
}

# ====== Bucle principal ======
while true; do
    clear
    echo -e "${BLUE}Corregir errores:"
    echo -e "====================${RESET}"
    i=1
    declare -A opciones
    for tipo in "${!grupos[@]}"; do
        nombre="${nombres_legibles[$tipo]:-$tipo}"
        echo -e "${PURPLE}$i.${RESET} $nombre"
        opciones["$i"]="$tipo"
        ((i++))
    done

    echo
    read -p "Seleccione una opción (o 0 para salir): " seleccion
    [[ "$seleccion" == "0" ]] && break
    tipo_elegido="${opciones[$seleccion]}"
    [[ -z "$tipo_elegido" ]] && continue

    # Detectar subtipos
    mapfile -t subtareas < <(echo "${grupos[$tipo_elegido]}" | grep -oE '^[A-Za-z0-9_]+:' | sed 's/://g' | sort -u)

    if (( ${#subtareas[@]} > 0 )); then
        echo
        echo "Subtipos en ${nombres_legibles[$tipo_elegido]:-$tipo_elegido}:"
        j=1
        declare -A subopciones
        for sub in "${subtareas[@]}"; do
            echo -e "${PURPLE}$j.${RESET} $sub"
            subopciones["$j"]="$sub"
            ((j++))
        done

        echo
        read -p "Seleccione un subtipo: " subsel
        subtipo="${subopciones[$subsel]}"
        [[ -z "$subtipo" ]] && continue

        mostrar_solucion "$tipo_elegido" "$subtipo" "${grupos[$tipo_elegido]}"
    else
        mostrar_solucion "$tipo_elegido" "" "${grupos[$tipo_elegido]}"
    fi
done
