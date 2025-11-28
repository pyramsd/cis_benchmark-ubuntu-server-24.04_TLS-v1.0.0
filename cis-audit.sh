#!/usr/bin/bash

echo "Sigue la estandarización de: cis_benchmark-ubuntu-server-24.04_TLS-v1.0.0"

source "$(dirname "$0")/constantes/Colores.sh"
source "$(dirname "$0")/functions/generate_report.sh"

if [ "$(id -u)" -ne 0 ]; then
    echo "Permiso denegado $0" >&2
    exit 1
fi

print_help() {
    cat <<'EOF'
Usage: ./cis-audit [-h | --help] [--fix-configs] [--allowed-programs=<path>] [--gen-report]

Opciones:
  -h, --help                        Muestra esta ayuda.
  --fix-configs                     Corrige las malas configuraciones de forma interactiva.
  --allowed-programs=<path_file>    Lee archivo de programas permitidos.
  --gen-report                      Genera un reporte de auditoría en formato Markdown.
EOF
}

FIX_CONFIGS=false
GEN_REPORT=false

PARSED=$(getopt -o h --long help,fix-configs,allowed-programs:,gen-report -- "$@")
if [ $? -ne 0 ]; then
    print_help
    exit 2
fi
eval set -- "$PARSED"

while true; do
    case "$1" in
        (-h|--help)
            print_help
            exit 0
            ;;
        (--fix-configs)
            FIX_CONFIGS=true
            source "$(dirname "$0")/solutions/fix_solutions.sh"
            exit 0
            ;;
        (--allowed-programs)
            ALLOWED_PROGRAMS_FILE="$2"
            shift 2
            ;;
        (--gen-report)
            GEN_REPORT=true
            shift
            ;;
        (--)
            shift   # quitar el separador "--"
            break   # salir del bucle de opciones
            ;;
        (*)
            # no debería ocurrir
            echo "Opción desconocida: $1" >&2
            exit 3
            ;;
    esac
done

LOG_DIR="$(dirname "$0")/logs"
mkdir -p "$LOG_DIR"
ERROR_LOG="$LOG_DIR/errors.log"
# Limpia el log de errores al inicio de cada ejecución para no arrastrar resultados antiguos.
: > "$ERROR_LOG"

# Redirigir todos los errores (stderr) de los scripts a un log, y también a la pantalla.
exec 2> >(tee -a "$ERROR_LOG")

# --- Ejecución de los Scripts de Auditoría ---
source 1_config_server_clients_services.sh
echo ""
source 2_config_cron_permissions.sh
echo ""
source 3_config_firewall.sh
echo ""
source 4_config_ssh_server.sh
echo ""
source 5_config_privilage_escalation.sh
echo ""
source 6_config_root_system_envs_accounts.sh
echo ""
source 7_config_usersgroups_local.sh
echo ""
source 8_config_system_file_permissions.sh

# Restaurar el descriptor de archivo de error estándar
exec 2>&1

echo "Los errores de configuración se guardarán en $ERROR_LOG"

# --- Generación del Reporte (si se solicitó) ---
if [ "$GEN_REPORT" = true ]; then
    echo "Generando reporte de auditoría..."
    generate_classified_report
fi