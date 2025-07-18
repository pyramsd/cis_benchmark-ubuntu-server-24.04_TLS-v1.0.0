echo -e "\e[1;34m[*] Configuracion de la cuenta root${RESET}"
# Array de comprobaciones: comando;valor_esperado;mensaje
checks=(
  "$(awk -F: '($3 == 0) { print $3 }' /etc/passwd);0;UID root"
  "$(awk -F: '($1 !~ /^(sync|shutdown|halt|operator)/ && $4=="0") {print $4}' /etc/passwd);0;GID de root"
  "$(awk -F: '$3=="0"{print $3}' /etc/group);0;Grupo root"
)

# Procesar cada verificación
for check in "${checks[@]}"; do
  IFS=";" read -r output expected label <<< "$check"
  if [[ "$output" == "$expected" ]]; then
    echo -e "${GREEN}[+] $label: $output${RESET}"
  else
    echo -e "${RED}[-] $label inesperado: $output${RESET}"
  fi
done
echo -e "\n"

echo -e "\e[1;34m[*] Estado de password de root${RESET}"
user_paswordState="$(passwd -S root | awk '{print $2}');L;Usuario root"
IFS=";" read -r output expected label <<< "$user_paswordState"
if [[ "$output" == "$expected" ]]; then
    echo -e "${GREEN}[+] $label: $output -> Locked${RESET}"
else
    echo -e "${RED}[-] $label inesperado: $output${RESET}"
fi

echo -e "\n"

echo -e "\e[1;34m[*] Integridad de la ruta root garantizada${RESET}"
# Inicialización de variables
l_output2=""                      # Almacena los mensajes de error
l_pmask="0022"                   # Máscara de permisos predeterminada
l_maxperm="$(printf '%o' $(( 0777 & ~$l_pmask )))"  # Permisos máximos seguros

# Obtener el PATH del usuario root
l_root_path="$(sudo -Hiu root env | grep '^PATH' | cut -d= -f2)"

# Dividir el PATH en un array
unset a_path_loc
IFS=":" read -ra a_path_loc <<< "$l_root_path"

# Validaciones de problemas comunes en el PATH
if grep -q "::" <<< "$l_root_path"; then
  l_output2="$l_output2\n - root's path contains an empty directory (::)"
fi

if grep -Pq ":\h*$" <<< "$l_root_path"; then
  l_output2="$l_output2\n - root's path contains a trailing (:)"
fi

if grep -Pq '(\h+|:)\.(:|\h*$)' <<< "$l_root_path"; then
  l_output2="$l_output2\n - root's path contains the current working directory (.)"
fi

# Verificar cada directorio en el PATH
for l_path in "${a_path_loc[@]}"; do
  if [ -d "$l_path" ]; then
    while read -r l_fmode l_fown; do
      if [ "$l_fown" != "root" ]; then
        l_output2="$l_output2\n - Directory: \"$l_path\" is owned by \"$l_fown\" but should be owned by \"root\""
      fi
      if [ $(( l_fmode & l_pmask )) -gt 0 ]; then
        l_output2="$l_output2\n - Directory: \"$l_path\" has mode \"$l_fmode\", but should be \"$l_maxperm\" or more restrictive"
      fi
    done <<< "$(stat -Lc '%#a %U' "$l_path")"
  else
    l_output2="$l_output2\n - \"$l_path\" is not a directory"
  fi
done

# Mostrar resultados de la auditoría con colores
if [ -z "$l_output2" ]; then
  echo -e "${GREEN}- Audit Result:\n *** PASS ***\n - Root's path is correctly configured${RESET}"
else
  echo -e "\e[38;5;210m- Audit Result:\n ** FAIL **\n - * Reasons for audit failure * :\n$l_output2${RESET}"
fi

echo -e "\n"

echo -e "\e[1;34m[*] Usuario root umask configurado${RESET}"
shell=$(basename "$SHELL")
output=$(grep -Psi -- '^\h*umask\h+(([0-7][0-7][01][0-7]\b|[0-7][0-7][0-7][0-6]\b)|([0-7][01][0-7]\b|[0-7][0-7][0-6]\b)|(u=[rwx]{1,3},)?(((g=[rx]?[rx]?w[rx]?[rx]?\b)(,o=[rwx]{1,3})?)|((g=[wrx]{1,3},)?o=[wrx]{1,3}\b)))' /root/.profile /root/.${shell}rc)
exit_code=$?
if [[ $exit_code -ne 0 ]]; then
        echo -e "${GREEN}[+] Usuario root umask correctamente configurado"
else
        ecjo -e "\e[38;5;210m[-] Usuario root umask incorrectamente configurado\n -> $output"
fi

echo -e "\n"

echo -e "\e[1;34m[*] Las cuentas del sistema no deben tener un shell de inicio valido${RESET}"
# Crear una lista de shells válidos a partir del archivo /etc/shells
l_valid_shells="^($(awk -F\/ '$NF != "nologin" {print}' /etc/shells | \
sed -rn '/^\//{s,/,\\\\/,g;p}' | paste -s -d '|' -))$"

# Obtener el UID mínimo definido en /etc/login.defs
uid_min=$(awk '/^\s*UID_MIN/ {print $2}' /etc/login.defs)

# Buscar y mostrar cuentas de servicio con shells válidos
result=$(awk -v pat="$l_valid_shells" -F: '
  ($1 !~ /^(root|halt|sync|shutdown|nfsnobody)$/ && 
   ($3 < '"$uid_min"' || $3 == 65534) && 
   $NF ~ pat) {
     print "Service account: \"" $1 "\" has a valid shell: " $7
}' /etc/passwd)

# Verificar si el resultado está vacío y mostrar mensajes con colores
if [[ -z "$result" ]]; then
        echo -e "${GREEN}[+] Servicios del sistema sin shell valido${RESET}"
else
        echo -e "\e[38;5;210m[!]Servicios del sistema con shell valido:${RESET}"
        echo "$result"
fi

echo -e "\n"

echo -e "\e[1;34m[*] Las cuentas sin un login shell válido deben estart bloqueadas${RESET}"
# Crear una lista de shells válidos a partir del archivo /etc/shells
l_valid_shells="^($(awk -F\/ '$NF != "nologin" {print}' /etc/shells | \
sed -rn '/^\//{s,/,\\\\/,g;p}' | paste -s -d '|' -))$"

# Buscar usuarios con shells inválidos y guardar en una variable
invalid_shell_users=$(awk -v pat="$l_valid_shells" -F: \
  '($1 != "root" && $(NF) !~ pat) {print $1}' /etc/passwd)

# Variable para almacenar resultados de cuentas no bloqueadas
output=""

# Verificar si los usuarios encontrados tienen la cuenta bloqueada
while IFS= read -r l_user; do
  # Comprobar el estado de la cuenta con `passwd -S`
  result=$(passwd -S "$l_user" | awk '
    $2 !~ /^L/ {print "Account: \"" $1 "\" does not have a valid login shell and is not locked"}')

  # Concatenar los resultados si hay cuentas no bloqueadas
  if [ -n "$result" ]; then
    output+="$result"$'\n'
  fi
done <<< "$invalid_shell_users"

# Mostrar mensajes de auditoría según el resultado
if [ -z "$output" ]; then
  # Si no hay resultados, la auditoría fue exitosa
  echo -e "${GREEN}Audit was successful: No issues found.${RESET}"
else
  # Si hay resultados, la auditoría falló
  echo -e "\e[38;5;210mAudit failed: Issues detected.${RESET}"
  echo "$output"
fi
