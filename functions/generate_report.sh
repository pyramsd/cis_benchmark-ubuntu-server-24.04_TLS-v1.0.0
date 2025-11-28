#!/usr/bin/bash

# functions/generate_report.sh

# Esta función lee el log de errores, los agrupa por tipo y genera un reporte en Markdown.
generate_classified_report() {
    local report_file="reporte_auditoria.md"
    local error_log="logs/errors.log"

    # --- Nombres legibles para las categorías de errores ---
    # (Extraído de fix_solutions.sh para consistencia)
    declare -A nombres_legibles=(
        ["FILE_PERMISSION"]="Permisos de Archivos"
        ["FIREWALL"]="Firewall"
        ["SOFTWARE"]="Software no recomendado"
        ["CONFIG"]="Errores de Configuración"
        ["PRIVILEGE"]="Escalada de Privilegios"
        ["ROOT_ACCOUNT"]="Configuración de la Cuenta Root"
        ["GROUP"]="Configuración de Grupos de Usuario"
        ["CIPHERS"]="Cifrados SSH Débiles"
        ["DUPLICATE_GROUPS"]="Nombres de Grupo Duplicados"
        ["DUPLICATE_GUIDs"]="GIDs Duplicados"
        ["DUPLICATE_NAMES"]="Nombres de Usuario Duplicados"
        ["DUPLICATE_UIDs"]="UIDs Duplicados"
        ["FILE"]="Archivos de Sistema Faltantes"
        ["GROUP_SHADOW"]="Miembros en Grupo Shadow"
        ["MTA_CONFIG"]="Configuración de MTA"
        ["PASSWD"]="Contraseñas en /etc/passwd"
        ["SHADOW"]="Cuentas sin Contraseña en /etc/shadow"
    )

    # --- 1. Agrupar los errores ---
    declare -A grouped_errors
    if [ ! -f "$error_log" ] || ! [ -s "$error_log" ]; then
        # Si el log no existe o está vacío, genera un reporte indicándolo.
        {
            echo "# Reporte de Auditoría CIS"
            echo ""
            echo "**Fecha de Generación:** $(date '+%Y-%m-%d %H:%M:%S')"
            echo "**Hostname:** $(hostname)"
            echo ""
            echo "---"
            echo ""
            echo "## ✨ No se encontraron errores durante la auditoría. ¡Felicidades! ✨"
        } > "$report_file"
        echo "Reporte generado en: $report_file"
        return 0
    fi

    # Lee el archivo de log y agrupa los mensajes por tipo de error
    while IFS= read -r line || [[ -n "$line" ]]; do
        if [[ "$line" =~ ^\[([A-Z_]+)\]\ (.*) ]]; then
            local type="${BASH_REMATCH[1]}"
            local message="${BASH_REMATCH[2]}"
            # Añade el mensaje al grupo correspondiente, con un salto de línea.
            grouped_errors["$type"]+="- ${message}\n"
        fi
    done < "$error_log"

    # --- 2. Generar el archivo de reporte ---
    {
        echo "# Reporte de Auditoría CIS"
        echo ""
        echo "**Fecha de Generación:** $(date '+%Y-%m-%d %H:%M:%S')"
        echo ""
        echo "**Hostname:** $(hostname)"

        # Itera sobre los grupos de errores y los escribe en el reporte
        for type in "${!grouped_errors[@]}"; do
            # Usar el nombre legible si existe, si no, usar el tipo de error crudo
            local title="${nombres_legibles[$type]:-$type}"
            echo "## Sección: $title"
            echo ""
            printf "%b" "${grouped_errors[$type]}"
            echo ""
            echo ""
        done
    } > "$report_file"

    echo "Reporte clasificado generado en: $report_file"
}
