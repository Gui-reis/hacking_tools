#!/bin/sh

###############################################################################
# LinPEAS Lite - versão simplificada e comentada
#
# Objetivo:
#   Fazer enumeração local de privilege escalation em Linux com menos ruído que
#   o LinPEAS original.
#
# Características importantes:
#   - Apenas enumeração passiva.
#   - Não explora vulnerabilidades automaticamente.
#   - Não altera arquivos.
#   - Não faz brute force.
#   - Não faz scan de rede externo.
#
# Uso típico:
#   chmod +x linpeas_lite.sh
#   ./linpeas_lite.sh
#
# Sem cores:
#   ./linpeas_lite.sh -n
###############################################################################

VERSION="0.1"

# Captura o hostname da máquina.
# Se o comando falhar, usa "unknown".
# 2>/dev/null joga erros fora para não poluir a saída.
HOSTNAME_VALUE="$(hostname 2>/dev/null || echo unknown)"

# Captura o usuário atual.
# Tenta whoami primeiro; se não existir/falhar, tenta id -un.
CURRENT_USER="$(whoami 2>/dev/null || id -un 2>/dev/null || echo unknown)"

###############################################################################
# Configuração de cores e opções
###############################################################################

# Por padrão, usamos cores.
USE_COLOR=1

# [ ! -t 1 ] significa: "stdout não é um terminal".
# Isso acontece, por exemplo, quando você redireciona a saída para arquivo:
#   ./linpeas_lite.sh > output.txt
# Nesse caso, desativamos cores para não sujar o arquivo com códigos ANSI.
[ ! -t 1 ] && USE_COLOR=0

# getopts lê opções curtas passadas ao script.
# Aqui aceitamos:
#   -n = no color
#   -h = help
while getopts "nh" opt; do
  case "$opt" in
    n)
      USE_COLOR=0
      ;;
    h)
      cat <<EOF
LinPEAS Lite v$VERSION

Usage: $0 [-n]

Options:
  -n   Disable colors
  -h   Show this help

This script performs passive local enumeration only.
EOF
      exit 0
      ;;
  esac
done

# Define códigos ANSI de cor se USE_COLOR=1.
# Se cores estiverem desabilitadas, as variáveis ficam vazias.
if [ "$USE_COLOR" -eq 1 ]; then
  RED='\033[1;31m'
  YELLOW='\033[1;33m'
  GREEN='\033[1;32m'
  BLUE='\033[1;34m'
  GRAY='\033[1;90m'
  NC='\033[0m'
else
  RED=''
  YELLOW=''
  GREEN=''
  BLUE=''
  GRAY=''
  NC=''
fi

###############################################################################
# Funções auxiliares de impressão
###############################################################################

print_banner() {
  printf "%b\n" "${BLUE}LinPEAS Lite v$VERSION${NC} - passive privilege escalation enumeration"
  printf "%b\n" "Host: ${HOSTNAME_VALUE} | User: ${CURRENT_USER}"
  printf "%b\n\n" "Authorized use only."
}

# Imprime o título grande de cada bloco.
section() {
  printf "\n%b\n" "${BLUE}========== $1 ==========${NC}"
}

# Mensagem informativa: contexto útil, mas não necessariamente vulnerável.
info() {
  printf "%b\n" "${GREEN}[INFO]${NC} $1"
}

# Mensagem de alta prioridade: algo que merece investigação manual.
warn() {
  printf "%b\n" "${YELLOW}[HIGH]${NC} $1"
}

# Mensagem crítica: algo que pode ser exploração direta ou quase direta.
crit() {
  printf "%b\n" "${RED}[CRITICAL]${NC} $1"
}

# Nota neutra, usada como subtítulo/explicação dentro dos blocos.
note() {
  printf "%b\n" "${GRAY}  $1${NC}"
}

###############################################################################
# Funções auxiliares de execução
###############################################################################

run_cmd() {
  # Uso:
  #   run_cmd "Descrição" "comando"
  #
  # Exemplo:
  #   run_cmd "Kernel:" "uname -a"
  #
  # sh -c "$2" executa o comando recebido como string.
  # 2>/dev/null remove erros da tela.
  # sed 's/^/  /' adiciona dois espaços no começo de cada linha da saída,
  # deixando o output visualmente indentado.

  note "$1"
  sh -c "$2" 2>/dev/null | sed 's/^/  /'
}

command_exists() {
  # Verifica se um comando existe no sistema.
  # Exemplo:
  #   command_exists sudo
  #
  # command -v retorna o caminho do comando se ele existir.
  # >/dev/null 2>&1 esconde stdout e stderr.

  command -v "$1" >/dev/null 2>&1
}

is_writable() {
  # Retorna verdadeiro se o caminho existe e é gravável pelo usuário atual.
  [ -e "$1" ] && [ -w "$1" ]
}

###############################################################################
# 1. Identidade e sistema
###############################################################################

check_identity_system() {
  section "1. Identity and system"

  # id mostra UID, GID e grupos do usuário atual.
  # Isso é uma das primeiras coisas a olhar em privesc.
  run_cmd "Current identity:" "id"

  # uname -a mostra kernel, arquitetura e algumas infos do sistema.
  # Kernel antigo pode indicar vulnerabilidades conhecidas.
  run_cmd "Kernel and architecture:" "uname -a"

  # /etc/os-release é o arquivo padrão moderno para identificar a distro.
  if [ -f /etc/os-release ]; then
    run_cmd "OS release:" "cat /etc/os-release | grep -E '^(PRETTY_NAME|NAME|VERSION)='"
  fi

  # Detecção simples de container.
  # /.dockerenv costuma existir dentro de containers Docker.
  # /proc/1/cgroup pode revelar docker/lxc/kubepods/containerd.
  if [ -f /.dockerenv ] || grep -qaE 'docker|lxc|kubepods|containerd' /proc/1/cgroup 2>/dev/null; then
    warn "Container indicators found. Container escape paths may be relevant."
    run_cmd "Container cgroup hints:" "cat /proc/1/cgroup | head -20"
  else
    info "No obvious container indicator found."
  fi
}

###############################################################################
# 2. Sudo e grupos
###############################################################################

check_sudo_groups() {
  section "2. Sudo and groups"

  # Guarda a saída de id em uma variável para reutilizar.
  groups_output="$(id 2>/dev/null)"
  echo "$groups_output" | sed 's/^/  /'

  # Alguns grupos são especialmente interessantes para privilege escalation.
  # Exemplos:
  #   docker -> frequentemente permite montar o filesystem do host.
  #   lxd    -> pode permitir abuso de containers privilegiados.
  #   disk   -> pode permitir leitura/escrita direta em discos.
  #   adm    -> pode permitir leitura de logs sensíveis.
  #   shadow -> pode permitir leitura de hashes de senha.
  for group in sudo wheel docker lxd adm disk shadow root; do
    echo "$groups_output" | grep -qw "$group" && warn "Current user appears to be in interesting group: $group"
  done

  if command_exists sudo; then
    # sudo -n -l tenta listar permissões sudo sem pedir senha.
    # O -n é importante porque evita o script ficar travado esperando input.
    note "sudo -l without password, if allowed by policy/cache:"
    sudo -n -l 2>/dev/null | sed 's/^/  /'

    # Captura a saída para classificar.
    sudo_nl="$(sudo -n -l 2>/dev/null)"

    if echo "$sudo_nl" | grep -qi 'NOPASSWD'; then
      crit "NOPASSWD sudo rule detected. Check listed binaries on GTFOBins."
    elif [ -n "$sudo_nl" ]; then
      warn "sudo -l returned data. Review allowed commands carefully."
    else
      info "No passwordless sudo info available with sudo -n -l."
    fi
  else
    info "sudo command not found."
  fi
}

###############################################################################
# 3. SUID e SGID
###############################################################################

check_suid_sgid() {
  section "3. SUID and SGID binaries"

  note "Known SUID binaries are normal. Focus on uncommon/custom paths like /opt, /home, /tmp, /usr/local."

  # SUID: binário executa com permissão do dono do arquivo.
  # Quando o dono é root, isso pode ser relevante.
  #
  # find /      -> começa na raiz.
  # -xdev       -> não cruza para outros filesystems montados.
  # -perm -4000 -> procura bit SUID.
  # -type f     -> só arquivos.
  suid_results="$(find / -xdev -perm -4000 -type f 2>/dev/null | sort)"

  if [ -n "$suid_results" ]; then
    echo "$suid_results" | sed 's/^/  /'

    # SUID em /usr/bin/passwd é normal.
    # SUID em /opt, /home, /tmp ou /usr/local pode ser custom e mais suspeito.
    echo "$suid_results" | grep -E '^/(home|opt|tmp|var/tmp|usr/local)/' >/dev/null 2>&1 \
      && crit "SUID binary found in uncommon writable-ish/custom path. Investigate first."
  else
    info "No SUID binaries found on current filesystem boundary."
  fi

  # SGID é parecido, mas relacionado ao grupo do arquivo.
  # Pode ser útil, mas costuma gerar mais ruído; por isso limitamos a 50 linhas.
  sgid_results="$(find / -xdev -perm -2000 -type f 2>/dev/null | sort | head -50)"
  if [ -n "$sgid_results" ]; then
    note "First SGID binaries found:"
    echo "$sgid_results" | sed 's/^/  /'
  fi
}

###############################################################################
# 4. Capabilities
###############################################################################

check_capabilities() {
  section "4. Capabilities"

  # getcap lista Linux capabilities associadas a binários.
  # Capabilities são como "pedaços" de privilégio root.
  if ! command_exists getcap; then
    info "getcap not found. Skipping capabilities."
    return
  fi

  caps="$(getcap -r / 2>/dev/null | sort)"

  if [ -z "$caps" ]; then
    info "No capabilities found or insufficient permissions to list them."
    return
  fi

  echo "$caps" | sed 's/^/  /'

  # Algumas capabilities são especialmente perigosas:
  #   cap_setuid          -> pode permitir virar outro UID, inclusive root.
  #   cap_setgid          -> pode permitir virar outro GID.
  #   cap_dac_read_search -> pode permitir burlar permissões de leitura.
  #   cap_dac_override    -> pode permitir burlar permissões de arquivo.
  echo "$caps" | grep -E 'cap_setuid|cap_setgid|cap_dac_read_search|cap_dac_override' >/dev/null 2>&1 \
    && crit "Dangerous capability detected. cap_setuid/cap_setgid/cap_dac_* can be privilege escalation relevant."
}

###############################################################################
# 5. Cron jobs e systemd timers
###############################################################################

check_cron_timers() {
  section "5. Cron jobs and systemd timers"

  # /etc/crontab pode mostrar tarefas periódicas globais.
  [ -f /etc/crontab ] && run_cmd "/etc/crontab:" "cat /etc/crontab"

  # Diretórios comuns de cron.
  # Se scripts nesses diretórios forem graváveis, pode ser crítico.
  for dir in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly; do
    [ -d "$dir" ] && run_cmd "Listing $dir:" "ls -la $dir"
  done

  # systemd timers são a alternativa moderna a muitos cron jobs.
  if command_exists systemctl; then
    run_cmd "Systemd timers:" "systemctl list-timers --all --no-pager | head -80"
  fi

  # Procura paths de cron graváveis pelo usuário atual.
  # Se root executa algo que você consegue escrever, isso pode virar privesc.
  note "Writable cron-related files/directories:"
  writable_cron="$(find /etc/cron* -writable 2>/dev/null)"

  if [ -n "$writable_cron" ]; then
    echo "$writable_cron" | sed 's/^/  /'
    crit "Writable cron path found. If root executes it, this may be exploitable."
  else
    info "No writable cron paths found under /etc/cron*."
  fi
}

###############################################################################
# 6. Processos e portas locais
###############################################################################

check_processes_ports() {
  section "6. Processes and local ports"

  # Lista uma amostra dos processos rodando como root.
  # Processos customizados ou scripts em /opt/home/var/www são interessantes.
  run_cmd "Root-owned processes with command preview:" "ps aux | awk '\$1 == \"root\" {print}' | head -40"

  # ss ou netstat mostram portas abertas.
  # Serviços escutando em 127.0.0.1 podem não aparecer externamente,
  # mas podem ser acessados localmente após foothold.
  if command_exists ss; then
    run_cmd "Listening TCP/UDP sockets:" "ss -tulpn"
  elif command_exists netstat; then
    run_cmd "Listening TCP/UDP sockets:" "netstat -tulpn"
  else
    info "Neither ss nor netstat found."
  fi

  note "Local-only services on 127.0.0.1 may be interesting for pivoting/tunneling in labs."
}

###############################################################################
# 7. Arquivos sensíveis e credenciais
###############################################################################

check_sensitive_files() {
  section "7. Sensitive files and credentials"

  # Procura chaves SSH legíveis.
  # Chaves privadas podem permitir login como outro usuário ou em outra máquina.
  note "SSH material in home directories:"
  find /home /root -maxdepth 3 \( \
    -name 'id_rsa' -o \
    -name 'id_dsa' -o \
    -name 'id_ecdsa' -o \
    -name 'id_ed25519' -o \
    -name 'authorized_keys' \
  \) -type f -readable 2>/dev/null | sed 's/^/  /'

  # Procura arquivos de configuração/backup/histórico comuns.
  # Esses arquivos frequentemente contêm senhas, tokens ou pistas de CTF.
  note "Common credential/config files in likely locations:"
  find /home /var/www /opt /srv /tmp -maxdepth 4 -type f \( \
    -name '.env' -o \
    -name '*.env' -o \
    -name 'config.php' -o \
    -name 'wp-config.php' -o \
    -name 'settings.py' -o \
    -name 'database.yml' -o \
    -name '*.bak' -o \
    -name '*.old' -o \
    -name '*.backup' -o \
    -name '*.sql' -o \
    -name '.bash_history' \
  \) -readable 2>/dev/null | sed 's/^/  /'

  # Busca rápida por palavras-chave em arquivos pequenos.
  # -size -200k evita grepar arquivos enormes.
  # grep -I ignora binários.
  # head -3 limita a quantidade de matches por arquivo.
  note "Quick keyword search in small readable config-like files:"
  find /home /var/www /opt /srv -maxdepth 4 -type f -readable -size -200k 2>/dev/null \
    | grep -Ei '(env|config|settings|database|backup|history|credential|secret|token|key|pass)' \
    | head -80 \
    | while read -r file; do
        match="$(grep -IinE 'password|passwd|pwd|secret|token|api[_-]?key|private[_-]?key|DB_PASSWORD|AWS_|BEGIN .*PRIVATE KEY' "$file" 2>/dev/null | head -3)"
        if [ -n "$match" ]; then
          warn "Potential secret in $file"
          echo "$match" | sed 's/^/    /'
        fi
      done
}

###############################################################################
# 8. Arquivos custom/interessantes legíveis, graváveis ou executáveis
###############################################################################

check_custom_interesting_files() {
  section "8. Custom/readable/writable/executable interesting files"

  note "Goal: find challenge/app/custom artifacts that are readable/writable/executable by the current user."
  note "This is intentionally focused on non-system locations to reduce noise."

  # Esses paths são menos barulhentos que buscar em / inteiro.
  #
  # Além dos caminhos clássicos de apps/dados (/home, /opt, /srv, /var/www...),
  # também tentamos descobrir diretórios custom criados diretamente na raiz.
  #
  # Exemplo:
  #   /incidents
  #   /backup
  #   /app
  #   /challenge
  #   /data

  BASE_SEARCH_PATHS="/home /opt /srv /var/www /var/backups /tmp"

  CUSTOM_ROOT_DIRS="$(find / -xdev -mindepth 1 -maxdepth 1 -type d 2>/dev/null \
    | grep -Ev '^/(bin|boot|dev|etc|home|lib|lib32|lib64|libx32|lost\+found|media|mnt|opt|proc|root|run|sbin|snap|srv|sys|tmp|usr|var)(/)?$' \
    | sort \
    | tr '
' ' ')"

  if [ -n "$CUSTOM_ROOT_DIRS" ]; then
    warn "Custom-looking root directories found: $CUSTOM_ROOT_DIRS"
  else
    info "No custom-looking root directories found."
  fi

  SEARCH_PATHS="$BASE_SEARCH_PATHS $CUSTOM_ROOT_DIRS"

  # Procura arquivos com nomes/extensões interessantes.
  # Aqui entram capturas de rede, logs, backups, bancos locais, envs,
  # arquivos com nomes contendo password/secret/token/etc.
  note "Readable interesting files by name/extension:"
  find $SEARCH_PATHS -xdev -type f -readable \( \
    -iname '*.pcap' -o \
    -iname '*.pcapng' -o \
    -iname '*.cap' -o \
    -iname '*.log' -o \
    -iname '*.txt' -o \
    -iname '*.md' -o \
    -iname '*.bak' -o \
    -iname '*.backup' -o \
    -iname '*.old' -o \
    -iname '*.zip' -o \
    -iname '*.tar' -o \
    -iname '*.tar.gz' -o \
    -iname '*.tgz' -o \
    -iname '*.sql' -o \
    -iname '*.db' -o \
    -iname '*.sqlite' -o \
    -iname '.env' -o \
    -iname '*.env' -o \
    -iname '*secret*' -o \
    -iname '*password*' -o \
    -iname '*passwd*' -o \
    -iname '*credential*' -o \
    -iname '*token*' -o \
    -iname '*key*' -o \
    -iname '*incident*' -o \
    -iname '*suspicious*' -o \
    -iname '*capture*' -o \
    -iname 'config.*' -o \
    -iname '*config*' \
  \) 2>/dev/null | sort | head -150 | while read -r file; do
    perms="$(ls -lh "$file" 2>/dev/null)"

    # Classificação simples:
    #   readable           -> pode conter pista/credencial/contexto.
    #   readable+writable  -> pode ser manipulável.
    #   readable+executable-> pode ser script/binário custom.
    if [ -w "$file" ]; then
      warn "Readable + writable interesting file: $file"
    elif [ -x "$file" ]; then
      warn "Readable + executable interesting file: $file"
    else
      info "Readable interesting file: $file"
    fi

    echo "  $perms"
  done

  # Procura executáveis custom em locais prováveis.
  # Se forem graváveis, marcamos como crítico, pois algum processo privilegiado
  # pode eventualmente executá-los.
  note "Executable custom files/scripts in likely custom locations:"
  find /home /opt /srv /var/www /tmp -xdev -type f -executable 2>/dev/null \
    | grep -Ev '/(node_modules|vendor|\.git|__pycache__)/' \
    | sort \
    | head -100 \
    | while read -r file; do
        if [ -w "$file" ]; then
          crit "Executable custom file is writable: $file"
        else
          warn "Executable custom file: $file"
        fi
        ls -lh "$file" 2>/dev/null | sed 's/^/  /'
      done

  # Procura arquivos graváveis em locais custom.
  # Isso pode gerar ruído, mas é útil em CTFs para achar scripts, configs e notas.
  note "Writable custom files in likely custom locations:"
  find /home /opt /srv /var/www /tmp -xdev -type f -writable 2>/dev/null \
    | grep -Ev '/(node_modules|vendor|\.git|__pycache__)/' \
    | sort \
    | head -100 \
    | while read -r file; do
        warn "Writable custom file: $file"
        ls -lh "$file" 2>/dev/null | sed 's/^/  /'
      done
}

###############################################################################
# 9. Permissões perigosas
###############################################################################

check_dangerous_permissions() {
  section "9. Dangerous permissions"

  # Esses arquivos são extremamente sensíveis.
  # Se o usuário atual conseguir escrever neles, normalmente é crítico.
  for file in /etc/passwd /etc/shadow /etc/sudoers; do
    if is_writable "$file"; then
      crit "$file is writable by current user."
      ls -la "$file" 2>/dev/null | sed 's/^/  /'
    else
      info "$file is not writable by current user."
    fi
  done

  # Procura arquivos/diretórios graváveis em locais sensíveis ou custom.
  # /etc             -> configs do sistema.
  # /opt             -> apps/scripts custom.
  # /usr/local/bin   -> binários/scripts custom no PATH.
  # /usr/local/sbin  -> binários admin custom.
  # /var/www         -> aplicações web.
  note "Writable files/directories in sensitive/custom locations:"
  find /etc /opt /usr/local/bin /usr/local/sbin /var/www -xdev -writable 2>/dev/null \
    | head -100 \
    | sed 's/^/  /'

  # Diretórios world-writable podem permitir abuso se forem usados por processos
  # privilegiados de forma insegura.
  # Excluímos /tmp e afins porque normalmente são world-writable por design.
  note "World-writable directories outside common noisy paths:"
  find / -xdev -type d -perm -0002 2>/dev/null \
    | grep -Ev '^/(proc|sys|dev|run|tmp|var/tmp)(/|$)' \
    | head -80 \
    | sed 's/^/  /'
}

###############################################################################
# Execução principal
###############################################################################

# O script é modular: cada função abaixo é um bloco independente.
# Para remover um bloco, basta comentar a chamada correspondente.

print_banner
check_identity_system
check_sudo_groups
check_suid_sgid
check_capabilities
check_cron_timers
check_processes_ports
check_sensitive_files
check_custom_interesting_files
check_dangerous_permissions

printf "\n%b\n" "${BLUE}Done.${NC} Review [CRITICAL] and [HIGH] findings first."
