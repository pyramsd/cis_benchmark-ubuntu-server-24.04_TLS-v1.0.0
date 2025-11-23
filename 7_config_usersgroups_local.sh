echo -e "${BLUE}[*] Cuentas de /etc/passwd utilizan contraseñas ocultas${RESET}"
output=$(awk -F: '($2 != "x" ) { print "User: \"" $1 "\" is not set to shadowed passwords "}' /etc/passwd)
exit_code=$?
if [[ $exit_code -eq 0 ]]; then
        echo -e "${GREEN}[+] Las cuentas usan clave secreta${RESET}"
        counter=$((counter + 1))
else
        echo -e "${RED}[-] Las cuentas no usan clave secreta:\n-> $output${RESET}"
        echo "[PASSWD] Las cuentas no usan clave secreta" >> "$LOG_FILE"
fi

echo -e "\n"

echo -e "${BLUE}[*] Campos de /etc/shadow password no estén vacíos${RESET}"
output=$(awk -F: '($2 == "" ) { print $1 " does not have a password "}' /etc/shadow)
exit_code=$?
if [[ $exit_code -eq 0 ]]; then
        echo -e "${GREEN}[+] Campos de /etc/shadow password no vacios${RESET}"
        counter=$((counter + 1))
else
        echo -e "${RED}[-] Campos de /etc/shadow password vacios:\n-> $output${RESET}"
        echo "[SHADOW] Campos de /etc/shadow password vacios" >> "$LOG_FILE"
fi

echo -e "\n"

echo -e "${BLUE}[*] Los grupos de /etc/passwd existen en /etc/group${RESET}"
# Obtener GIDs únicos desde /etc/passwd
mapfile -t a_passwd_group_gid < <(awk -F: '{print $4}' /etc/passwd | sort -u)

# Obtener GIDs únicos desde /etc/group
mapfile -t a_group_gid < <(awk -F: '{print $3}' /etc/group | sort -u)

# Identificar GIDs en /etc/passwd que no están en /etc/group
mapfile -t a_passwd_group_diff < <(
    printf '%s\n' "${a_passwd_group_gid[@]}" "${a_group_gid[@]}" | sort | uniq -u
)

# Verificar y mostrar usuarios con GIDs inexistentes en /etc/group
if [ ${#a_passwd_group_diff[@]} -eq 0 ]; then
        echo -e "${GREEN}[+] Todos los grupos de /etc/passwd existen en /etc/group"
        counter=$((counter + 1))
else
        echo -e "${PINK}[!] Algunos GIDs de /etc/passwd no existen en /etc/group:"
        echo ${a_passwd_group_diff[@]}
        for l_gid in "${a_passwd_group_diff[@]}"; do
                awk -F: -v gid="$l_gid" '
                        $4 == gid {
                                print " - User: \"" $1 "\" has GID: \"" $4 "\" which does not exist in /etc/group"
                        }
                ' /etc/passwd
        done
        echo "[GROUP] Algunos GIDs de /etc/passwd no existen en /etc/group" >> "$LOG_FILE"
fi

# Limpiar variables
unset a_passwd_group_gid
unset a_group_gid
unset a_passwd_group_diff

echo -e "\n"

echo -e "${BLUE}[*] Grupo shadow vacio${RESET}"
output1=$(awk -F: '($1=="shadow") {print $NF}' /etc/group)
exit_code1=$?
output2=$(awk -F: '($4 == '"$(getent group shadow | awk -F: '{print $3}' | xargs)"') {print " - user: \"" $1 "\" primary group is the shadow group"}' /etc/passwd)
exit_code2=$?
if [[ $exit_code1 -eq 0 && $exit_code2 -eq 0 ]]; then
        echo -e "${GREEN}[+] Grupo shadow vacio"
        counter=$((counter + 1))
else
        echo -e "${RED}[-] Grupo shadow no vacio\n-> $output1\n-> $output2"
        echo "[GROUP_SHADOW] Grupo shadow no vacio" >> "$LOG_FILE"
fi

echo -e "\n"

echo -e "${BLUE}[*] UIDs duplicados no existente${RESET}"
{
    # Inicializar una variable para rastrear duplicados
    has_duplicates=0

    # Leer y procesar las líneas de UIDs únicos y sus recuentos
    while read -r l_count l_uid; do
        # Verificar si el UID está duplicado
        if [ "$l_count" -gt 1 ]; then
            # Marcar que se encontraron duplicados
            has_duplicates=1
            # Mostrar el UID duplicado y los usuarios asociados en rojo
            echo -e "${RED}- Duplicate UID: \"$l_uid\" Users: \"$(awk -F: -v n="$l_uid" '($3 == n) { print $1 }' /etc/passwd | xargs)\"${RESET}"
        fi
    done < <(cut -f3 -d":" /etc/passwd | sort -n | uniq -c)

    # Verificar si hubo duplicados
    if [ "$has_duplicates" -eq 0 ]; then
        # Si no hay duplicados, mostrar mensaje en verde
        echo -e "${GREEN}[+] No duplicate UIDs found in /etc/passwd${RESET}"
        counter=$((counter + 1))
    else
        # Si hubo duplicados, mostrar mensaje adicional en rojo
        echo -e "${RED}[-] Some duplicate UIDs were found in /etc/passwd${RESET}"
        echo "[DUPLICATE_UIDs] Existen UIDs duplicados" >> "$LOG_FILE"
    fi
}

echo -e "\n"

echo -e "${BLUE}[*] GIDs duplicados no existente${RESET}"
{
    # Inicializar una variable para rastrear duplicados
    has_duplicates=0

    # Leer y procesar las líneas de UIDs únicos y sus recuentos
    while read -r l_count l_gid; do
        # Verificar si el UID está duplicado
        if [ "$l_count" -gt 1 ]; then
            # Marcar que se encontraron duplicados
            has_duplicates=1
            # Mostrar el UID duplicado y los usuarios asociados en rojo
            echo -e "${RED}- Duplicate GID: \"$l_gid\" Grupos: \"$(awk -F: -v n="$l_gid" '($3 == n) { print $1 }' /etc/group | xargs)\"${RESET}"
        fi
    done < <(cut -f3 -d":" /etc/group | sort -n | uniq -c)

    # Verificar si hubo duplicados
    if [ "$has_duplicates" -eq 0 ]; then
        # Si no hay duplicados, mostrar mensaje en verde
        echo -e "${GREEN}[+] No duplicate GIDs found in /etc/group${RESET}"
        counter=$((counter + 1))
    else
        # Si hubo duplicados, mostrar mensaje adicional en rojo
        echo -e "${RED}[-] Some duplicate GIDs were found in /etc/group${RESET}"
        echo "[DUPLICATE_GUIDs] Existen GUIDs duplicados" >> "$LOG_FILE"
    fi
}

echo -e "\n"

echo -e "${BLUE}[*] Usuarios duplicados no existente${RESET}"
{
    # Inicializar una variable para rastrear duplicados
    has_duplicates=0

    # Leer y procesar las líneas de UIDs únicos y sus recuentos
    while read -r l_count l_user; do
        # Verificar si el UID está duplicado
        if [ "$l_count" -gt 1 ]; then
            # Marcar que se encontraron duplicados
            has_duplicates=1
            # Mostrar el UID duplicado y los usuarios asociados en rojo
            echo -e "${RED}- Duplicate User: \"$l_user\" Users: \"$(awk -F: -v n="$l_user" '($1 == n) { print $1 }' /etc/passwd | xargs)\"${RESET}"
        fi
    done < <(cut -f1 -d":" /etc/passwd | sort | uniq -c)

    # Verificar si hubo duplicados
    if [ "$has_duplicates" -eq 0 ]; then
        # Si no hay duplicados, mostrar mensaje en verde
        echo -e "${GREEN}[+] No duplicate names found in /etc/passwd${RESET}"
        counter=$((counter + 1))
    else
        # Si hubo duplicados, mostrar mensaje adicional en rojo
        echo -e "${RED}[-] Some duplicate names were found in /etc/passwd${RESET}"
        echo "[DUPLICATE_NAMES] Existen nombres duplicados" >> "$LOG_FILE"
    fi
}

echo -e "\n"

echo -e "${BLUE}[*] Grupos duplicado no existente${RESET}"
{
    # Inicializar una variable para rastrear duplicados
    has_duplicates=0

    # Leer y procesar las líneas de UIDs únicos y sus recuentos
    while read -r l_count l_group; do
        # Verificar si el UID está duplicado
        if [ "$l_count" -gt 1 ]; then
            # Marcar que se encontraron duplicados
            has_duplicates=1
            # Mostrar el UID duplicado y los usuarios asociados en rojo
            echo -e "${RED}- Duplicate Group: \"$l_group\" Groups: \"$(awk -F: -v n="$l_group" '($1 == n) { print $1 }' /etc/group | xargs)\"${RESET}"
        fi
    done < <(cut -f1 -d":" /etc/group | sort | uniq -c)

    # Verificar si hubo duplicados
    if [ "$has_duplicates" -eq 0 ]; then
        # Si no hay duplicados, mostrar mensaje en verde
        echo -e "${GREEN}[+] No duplicate groups found in /etc/group${RESET}"
        counter=$((counter + 1))
    else
        # Si hubo duplicados, mostrar mensaje adicional en rojo
        echo -e "${RED}[-] Some duplicate groups were found in /etc/group${RESET}"
        echo "[DUPLICATE_GROUPS] Existen grupos duplicados" >> "$LOG_FILE"
    fi
}
