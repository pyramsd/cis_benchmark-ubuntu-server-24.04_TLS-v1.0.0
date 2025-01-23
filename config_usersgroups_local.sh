echo -e "\e[34m[*] Cuentas de /etc/passwd utilizan contraseñas ocultas"
output=$(awk -F: '($2 != "x" ) { print "User: \"" $1 "\" is not set to shadowed passwords "}' /etc/passwd)
exit_code=$?
if [[ $exit_code -eq 0 ]]; then
        echo -e "\e[32m[+] Las cuentas usan clave secreta\e[0m"
else
        echo -e "\e[31m[-] Las cuentas no usan clave secreta:\n-> $output\e[0m"
fi

echo -e "\n"

echo -e "\e[34m[*] Campos de /etc/shadow password no estén vacíos"
output=$(awk -F: '($2 == "" ) { print $1 " does not have a password "}' /etc/shadow)
exit_code=$?
if [[ $exit_code -eq 0 ]]; then
        echo -e "\e[32m[+] Campos de /etc/shadow password no vacios\e[0m"
else
        echo -e "\e[31m[-] Campos de /etc/shadow password vacios:\n-> $output\e[0m"
fi

echo -e "\n"

echo -e "\e[34m[*] Los grupos de /etc/passwd existen en /etc/group"
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
        echo -e "\e[32m[+] Todos los grupos de /etc/passwd existen en /etc/group"
else
        echo -e "\e[38;5;210m[!] Algunos GIDs de /etc/passwd no existen en /etc/group:"
        echo ${a_passwd_group_diff[@]}
        for l_gid in "${a_passwd_group_diff[@]}"; do
                awk -F: -v gid="$l_gid" '
                        $4 == gid {
                                print " - User: \"" $1 "\" has GID: \"" $4 "\" which does not exist in /etc/group"
                        }
                ' /etc/passwd
        done
fi

# Limpiar variables
unset a_passwd_group_gid
unset a_group_gid
unset a_passwd_group_diff

echo -e "\n"

echo -e "\e[34m[*] Grupo shadow vacio"
output1=$(awk -F: '($1=="shadow") {print $NF}' /etc/group)
exit_code1=$?
output2=$(awk -F: '($4 == '"$(getent group shadow | awk -F: '{print $3}' | xargs)"') {print " - user: \"" $1 "\" primary group is the shadow group"}' /etc/passwd)
exit_code2=$?
if [[ $exit_code1 -eq 0 && $exit_code2 -eq 0 ]]; then
        echo -e "\e[32m[+] Grupo shadow vacio"
else
        echo -e "\e[31m[-] Grupo shadow no vacia\n-> $output1\n-> $output2"
fi

echo -e "\n"

echo -e "\e[34m[*] UIDs duplicados no existente"
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
            echo -e "\e[31m- Duplicate UID: \"$l_uid\" Users: \"$(awk -F: -v n="$l_uid" '($3 == n) { print $1 }' /etc/passwd | xargs)\"\e[0m"
        fi
    done < <(cut -f3 -d":" /etc/passwd | sort -n | uniq -c)

    # Verificar si hubo duplicados
    if [ "$has_duplicates" -eq 0 ]; then
        # Si no hay duplicados, mostrar mensaje en verde
        echo -e "\e[32m[+] No duplicate UIDs found in /etc/passwd\e[0m"
    else
        # Si hubo duplicados, mostrar mensaje adicional en rojo
        echo -e "\e[31m[-] Some duplicate UIDs were found in /etc/passwd\e[0m"
    fi
}

echo -e "\n"

echo -e "\e[34m[*] GIDs duplicados no existente"
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
            echo -e "\e[31m- Duplicate GID: \"$l_gid\" Grupos: \"$(awk -F: -v n="$l_gid" '($3 == n) { print $1 }' /etc/group | xargs)\"\e[0m"
        fi
    done < <(cut -f3 -d":" /etc/group | sort -n | uniq -c)

    # Verificar si hubo duplicados
    if [ "$has_duplicates" -eq 0 ]; then
        # Si no hay duplicados, mostrar mensaje en verde
        echo -e "\e[32m[+] No duplicate GIDs found in /etc/group\e[0m"
    else
        # Si hubo duplicados, mostrar mensaje adicional en rojo
        echo -e "\e[31m[-] Some duplicate GIDs were found in /etc/group\e[0m"
    fi
}

echo -e "\n"

echo -e "\e[34m[*] Usuarios duplicados no existente"
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
            echo -e "\e[31m- Duplicate User: \"$l_user\" Users: \"$(awk -F: -v n="$l_user" '($1 == n) { print $1 }' /etc/passwd | xargs)\"\e[0m"
        fi
    done < <(cut -f3 -d":" /etc/group | sort -n | uniq -c)

    # Verificar si hubo duplicados
    if [ "$has_duplicates" -eq 0 ]; then
        # Si no hay duplicados, mostrar mensaje en verde
        echo -e "\e[32m[+] No duplicate names found in /etc/group\e[0m"
    else
        # Si hubo duplicados, mostrar mensaje adicional en rojo
        echo -e "\e[31m[-] Some duplicate names were found in /etc/group\e[0m"
    fi
}

echo -e "\n"

echo -e "\e[34m[*] Grupos duplicado no existente"
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
            echo -e "\e[31m- Duplicate Group: \"$l_user\" Groups: \"$(awk -F: -v n="$l_group" '($1 == n) { print $1 }' /etc/group | xargs)\"\e[0m"
        fi
    done < <(cut -f3 -d":" /etc/group | sort -n | uniq -c)

    # Verificar si hubo duplicados
    if [ "$has_duplicates" -eq 0 ]; then
        # Si no hay duplicados, mostrar mensaje en verde
        echo -e "\e[32m[+] No duplicate groups found in /etc/group\e[0m"
    else
        # Si hubo duplicados, mostrar mensaje adicional en rojo
        echo -e "\e[31m[-] Some duplicate groups were found in /etc/group\e[0m"
    fi
}
