#!/bin/sh

###############################################################################
# PCAP Lite - versão simplificada e comentada
#
# Objetivo:
#   Analisar arquivos .pcap/.pcapng em busca de informações úteis em CTFs,
#   pentests autorizados e labs: protocolos, conversas, HTTP, FTP, DNS,
#   strings suspeitas, caminhos, usuários, senhas, tokens e streams TCP.
#
# Características importantes:
#   - Análise offline de arquivo de captura.
#   - Não envia tráfego para rede.
#   - Não altera o arquivo original.
#   - Não tenta explorar nada automaticamente.
#
# Dependências recomendadas:
#   tshark   -> principal ferramenta, versão CLI do Wireshark.
#   strings  -> fallback simples para extrair texto do arquivo.
#   grep/sed/sort/head -> normalmente já existem no Linux.
#
# Instalação do tshark em Debian/Ubuntu/Kali:
#   sudo apt update
#   sudo apt install tshark
#
# Uso:
#   chmod +x pcap_lite.sh
#   ./pcap_lite.sh suspicious.pcapng
#
# Sem cores:
#   ./pcap_lite.sh -n suspicious.pcapng
#
# Mais streams TCP:
#   ./pcap_lite.sh -s 20 suspicious.pcapng
###############################################################################

VERSION="0.1"
USE_COLOR=1
MAX_STREAMS=10
MAX_LINES=80
PCAP_FILE=""

###############################################################################
# Leitura de opções
###############################################################################

# Opções:
#   -n      desativa cores
#   -s N    número máximo de TCP streams para inspecionar
#   -h      ajuda
while getopts "hns:" opt; do
  case "$opt" in
    n)
      USE_COLOR=0
      ;;
    s)
      MAX_STREAMS="$OPTARG"
      ;;
    h)
      cat <<EOF
PCAP Lite v$VERSION

Usage:
  $0 [-n] [-s MAX_STREAMS] <file.pcap|file.pcapng>

Options:
  -n              Disable colors
  -s MAX_STREAMS  Max TCP streams to inspect with follow,tcp,ascii. Default: 10
  -h              Show help

Examples:
  $0 suspicious.pcapng
  $0 -n suspicious.pcapng
  $0 -s 20 suspicious.pcapng
EOF
      exit 0
      ;;
  esac
done

# shift remove as opções já processadas por getopts.
# Depois disso, $1 deve ser o arquivo pcap/pcapng.
shift $((OPTIND - 1))
PCAP_FILE="$1"

###############################################################################
# Validação básica
###############################################################################

if [ -z "$PCAP_FILE" ]; then
  echo "ERROR: Missing pcap/pcapng file. Use -h for help." >&2
  exit 1
fi

if [ ! -f "$PCAP_FILE" ]; then
  echo "ERROR: File not found: $PCAP_FILE" >&2
  exit 1
fi

# Valida se MAX_STREAMS é número inteiro positivo.
case "$MAX_STREAMS" in
  ''|*[!0-9]*)
    echo "ERROR: -s requires a positive integer." >&2
    exit 1
    ;;
esac

###############################################################################
# Cores
###############################################################################

# Se stdout não for terminal, removemos cores automaticamente.
# Exemplo:
#   ./pcap_lite.sh suspicious.pcapng > report.txt
[ ! -t 1 ] && USE_COLOR=0

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

section() {
  printf "\n%b\n" "${BLUE}========== $1 ==========${NC}"
}

info() {
  printf "%b\n" "${GREEN}[INFO]${NC} $1"
}

warn() {
  printf "%b\n" "${YELLOW}[HIGH]${NC} $1"
}

crit() {
  printf "%b\n" "${RED}[CRITICAL]${NC} $1"
}

note() {
  printf "%b\n" "${GRAY}  $1${NC}"
}

###############################################################################
# Funções auxiliares gerais
###############################################################################

command_exists() {
  command -v "$1" >/dev/null 2>&1
}

need_tshark() {
  # Retorna verdadeiro se tshark existe.
  # Alguns blocos dependem fortemente dele; outros usam fallback com strings.
  command_exists tshark
}

print_banner() {
  printf "%b\n" "${BLUE}PCAP Lite v$VERSION${NC} - offline pcap/pcapng triage"
  printf "%b\n" "File: $PCAP_FILE"
  printf "%b\n\n" "Authorized/educational analysis only."
}

###############################################################################
# 1. Checagem de dependências
###############################################################################

check_dependencies() {
  section "1. Dependencies"

  if need_tshark; then
    info "tshark found. Full analysis enabled."
    tshark -v 2>/dev/null | head -1 | sed 's/^/  /'
  else
    warn "tshark not found. Only limited strings-based analysis will run."
    note "Install on Debian/Ubuntu/Kali with: sudo apt install tshark"
  fi

  if command_exists strings; then
    info "strings found. Text extraction enabled."
  else
    warn "strings not found. Suspicious text extraction will be limited."
  fi
}

###############################################################################
# 2. Resumo do arquivo
###############################################################################

basic_file_info() {
  section "2. Basic file info"

  note "Filesystem metadata:"
  ls -lh "$PCAP_FILE" 2>/dev/null | sed 's/^/  /'

  if command_exists file; then
    note "File type:"
    file "$PCAP_FILE" 2>/dev/null | sed 's/^/  /'
  fi

  if need_tshark; then
    note "First packets preview:"
    tshark -r "$PCAP_FILE" 2>/dev/null | head -20 | sed 's/^/  /'
  fi
}

###############################################################################
# 3. Hierarquia de protocolos
###############################################################################

protocol_summary() {
  section "3. Protocol summary"

  if ! need_tshark; then
    warn "Skipping protocol summary because tshark is missing."
    return
  fi

  # -q deixa o tshark mais quieto.
  # -z io,phs pede a estatística Protocol Hierarchy Statistics.
  # Isso mostra quais protocolos aparecem no arquivo: tcp, http, ftp, dns etc.
  tshark -r "$PCAP_FILE" -q -z io,phs 2>/dev/null | sed 's/^/  /'
}

###############################################################################
# 4. Conversas TCP/UDP
###############################################################################

conversation_summary() {
  section "4. TCP/UDP conversations"

  if ! need_tshark; then
    warn "Skipping conversations because tshark is missing."
    return
  fi

  # Conversas ajudam a entender quem falou com quem e em quais portas.
  # Em CTF, isso costuma revelar FTP, HTTP, reverse shell, banco local etc.
  note "TCP conversations:"
  tshark -r "$PCAP_FILE" -q -z conv,tcp 2>/dev/null | sed 's/^/  /'

  note "UDP conversations:"
  tshark -r "$PCAP_FILE" -q -z conv,udp 2>/dev/null | sed 's/^/  /'
}

###############################################################################
# 5. HTTP
###############################################################################

http_analysis() {
  section "5. HTTP analysis"

  if ! need_tshark; then
    warn "Skipping HTTP analysis because tshark is missing."
    return
  fi

  # Lista requests HTTP em formato tabular.
  # -Y aplica display filter do Wireshark.
  # -T fields imprime campos específicos.
  note "HTTP requests:"
  http_requests="$(tshark -r "$PCAP_FILE" -Y 'http.request' -T fields \
    -e frame.number \
    -e frame.time \
    -e ip.src \
    -e ip.dst \
    -e http.host \
    -e http.request.method \
    -e http.request.uri 2>/dev/null | head -$MAX_LINES)"

  if [ -n "$http_requests" ]; then
    echo "$http_requests" | sed 's/^/  /'
  else
    info "No HTTP requests found."
  fi

  # POSTs são especialmente interessantes porque podem conter login/senha/token.
  note "HTTP POST requests:"
  http_posts="$(tshark -r "$PCAP_FILE" -Y 'http.request.method == "POST"' -T fields \
    -e frame.number \
    -e frame.time \
    -e ip.src \
    -e ip.dst \
    -e http.host \
    -e http.request.uri 2>/dev/null | head -$MAX_LINES)"

  if [ -n "$http_posts" ]; then
    warn "HTTP POST traffic found. Inspect these streams/packets for credentials."
    echo "$http_posts" | sed 's/^/  /'
  else
    info "No HTTP POST requests found."
  fi

  # Tenta extrair Authorization headers.
  # Em tráfego HTTP claro, Basic/Bearer tokens podem aparecer aqui.
  note "HTTP Authorization headers, if present:"
  auth_headers="$(tshark -r "$PCAP_FILE" -Y 'http.authorization' -T fields \
    -e frame.number \
    -e ip.src \
    -e ip.dst \
    -e http.authorization 2>/dev/null | head -$MAX_LINES)"

  if [ -n "$auth_headers" ]; then
    crit "HTTP Authorization header found. This may contain credentials/tokens."
    echo "$auth_headers" | sed 's/^/  /'
  else
    info "No HTTP Authorization headers found."
  fi

  # Cookies às vezes carregam sessão/token.
  note "HTTP Cookie headers, if present:"
  cookies="$(tshark -r "$PCAP_FILE" -Y 'http.cookie' -T fields \
    -e frame.number \
    -e ip.src \
    -e ip.dst \
    -e http.cookie 2>/dev/null | head -$MAX_LINES)"

  if [ -n "$cookies" ]; then
    warn "HTTP Cookie header found. Session data may be present."
    echo "$cookies" | sed 's/^/  /'
  else
    info "No HTTP Cookie headers found."
  fi
}

###############################################################################
# 6. FTP
###############################################################################

ftp_analysis() {
  section "6. FTP analysis"

  if ! need_tshark; then
    warn "Skipping FTP analysis because tshark is missing."
    return
  fi

  # FTP clássico envia USER/PASS em texto claro.
  # Em CTFs, isso é uma das maiores fontes de credenciais.
  note "FTP USER/PASS commands:"
  ftp_creds="$(tshark -r "$PCAP_FILE" -Y 'ftp.request.command == "USER" || ftp.request.command == "PASS"' -T fields \
    -e frame.number \
    -e frame.time \
    -e ip.src \
    -e ip.dst \
    -e ftp.request.command \
    -e ftp.request.arg 2>/dev/null | head -$MAX_LINES)"

  if [ -n "$ftp_creds" ]; then
    crit "FTP credentials found in cleartext."
    echo "$ftp_creds" | sed 's/^/  /'
  else
    info "No FTP USER/PASS commands found."
  fi

  note "Other FTP commands:"
  ftp_cmds="$(tshark -r "$PCAP_FILE" -Y 'ftp.request' -T fields \
    -e frame.number \
    -e ip.src \
    -e ip.dst \
    -e ftp.request.command \
    -e ftp.request.arg 2>/dev/null | head -$MAX_LINES)"

  if [ -n "$ftp_cmds" ]; then
    echo "$ftp_cmds" | sed 's/^/  /'
  else
    info "No FTP commands found."
  fi
}

###############################################################################
# 7. DNS
###############################################################################

dns_analysis() {
  section "7. DNS analysis"

  if ! need_tshark; then
    warn "Skipping DNS analysis because tshark is missing."
    return
  fi

  # DNS pode revelar domínios internos, C2, nomes de hosts e pistas.
  note "DNS queries:"
  dns_queries="$(tshark -r "$PCAP_FILE" -Y 'dns.flags.response == 0' -T fields \
    -e frame.number \
    -e ip.src \
    -e ip.dst \
    -e dns.qry.name 2>/dev/null | sort -u | head -$MAX_LINES)"

  if [ -n "$dns_queries" ]; then
    echo "$dns_queries" | sed 's/^/  /'
  else
    info "No DNS queries found."
  fi
}

###############################################################################
# 8. Outros protocolos de texto claro
###############################################################################

cleartext_protocols_analysis() {
  section "8. Other cleartext protocol hints"

  if ! need_tshark; then
    warn "Skipping protocol-specific checks because tshark is missing."
    return
  fi

  # Telnet é texto claro.
  telnet_count="$(tshark -r "$PCAP_FILE" -Y 'telnet' 2>/dev/null | wc -l | tr -d ' ')"
  [ "$telnet_count" -gt 0 ] 2>/dev/null && crit "Telnet traffic found. Credentials may be visible in TCP streams."

  # SMTP/POP/IMAP sem TLS podem conter credenciais/comandos em texto.
  smtp_count="$(tshark -r "$PCAP_FILE" -Y 'smtp || pop || imap' 2>/dev/null | wc -l | tr -d ' ')"
  [ "$smtp_count" -gt 0 ] 2>/dev/null && warn "Mail protocol traffic found. Check for cleartext auth or sensitive content."

  # SMB pode ter nomes de arquivos/hosts/usuários interessantes, mesmo sem senha clara.
  smb_count="$(tshark -r "$PCAP_FILE" -Y 'smb || smb2' 2>/dev/null | wc -l | tr -d ' ')"
  [ "$smb_count" -gt 0 ] 2>/dev/null && warn "SMB traffic found. Check hostnames, shares, files and auth attempts."

  # SSH normalmente não revela senha, mas mostra conexões e pode indicar reverse shell/túnel.
  ssh_count="$(tshark -r "$PCAP_FILE" -Y 'ssh' 2>/dev/null | wc -l | tr -d ' ')"
  [ "$ssh_count" -gt 0 ] 2>/dev/null && info "SSH traffic found. Content is encrypted, but endpoints/timing may matter."

  if [ "${telnet_count:-0}" -eq 0 ] 2>/dev/null && \
     [ "${smtp_count:-0}" -eq 0 ] 2>/dev/null && \
     [ "${smb_count:-0}" -eq 0 ] 2>/dev/null && \
     [ "${ssh_count:-0}" -eq 0 ] 2>/dev/null; then
    info "No Telnet/SMTP/POP/IMAP/SMB/SSH hints found by protocol filters."
  fi
}

###############################################################################
# 9. Extração de strings suspeitas
###############################################################################

strings_analysis() {
  section "9. Suspicious strings"

  if ! command_exists strings; then
    warn "strings command not found. Skipping."
    return
  fi

  # strings extrai trechos imprimíveis do arquivo binário.
  # É uma abordagem burra, mas muito útil em CTF.
  # Muitas vezes revela USER/PASS, comandos HTTP, caminhos, scripts e tokens.

  note "Credential-like strings:"
  cred_strings="$(strings "$PCAP_FILE" 2>/dev/null \
    | grep -Eai 'user(name)?=|login=|pass(word)?=|passwd=|pwd=|secret=|token=|api[_-]?key=|authorization:|bearer |basic |USER |PASS ' \
    | head -$MAX_LINES)"

  if [ -n "$cred_strings" ]; then
    warn "Credential-like strings found. Review carefully."
    echo "$cred_strings" | sed 's/^/  /'
  else
    info "No obvious credential-like strings found."
  fi

  note "Interesting paths/files mentioned in capture:"
  path_strings="$(strings "$PCAP_FILE" 2>/dev/null \
    | grep -Eai '(/home/|/root/|/var/www/|/etc/passwd|/etc/shadow|/tmp/|/opt/|\.php|\.sh|\.py|\.txt|\.zip|\.tar|\.sql|\.db|\.pcap|\.pcapng|id_rsa|authorized_keys)' \
    | head -$MAX_LINES)"

  if [ -n "$path_strings" ]; then
    warn "Interesting path/file strings found."
    echo "$path_strings" | sed 's/^/  /'
  else
    info "No obvious path/file strings found."
  fi

  note "Command/shell-like strings:"
  cmd_strings="$(strings "$PCAP_FILE" 2>/dev/null \
    | grep -Eai '(bash -i|/bin/bash|/bin/sh|nc -e|netcat|python.*socket|perl.*socket|php.*system|cmd=|whoami|id;|uname -a|cat /etc/passwd|chmod|chown|sudo|su )' \
    | head -$MAX_LINES)"

  if [ -n "$cmd_strings" ]; then
    warn "Shell/command-like strings found. Possible webshell/reverse shell activity."
    echo "$cmd_strings" | sed 's/^/  /'
  else
    info "No obvious shell/command-like strings found."
  fi
}

###############################################################################
# 10. TCP streams suspeitos
###############################################################################

stream_analysis() {
  section "10. Suspicious TCP streams"

  if ! need_tshark; then
    warn "Skipping TCP stream analysis because tshark is missing."
    return
  fi

  # tcp.stream é o número do fluxo TCP atribuído pelo Wireshark/tshark.
  # Primeiro listamos os stream IDs existentes.
  streams="$(tshark -r "$PCAP_FILE" -T fields -e tcp.stream 2>/dev/null \
    | grep -E '^[0-9]+$' \
    | sort -n \
    | uniq \
    | head -$MAX_STREAMS)"

  if [ -z "$streams" ]; then
    info "No TCP streams found."
    return
  fi

  note "Inspecting up to $MAX_STREAMS TCP streams for suspicious text."

  # Para cada stream, usamos:
  #   -z follow,tcp,ascii,N
  # Isso é equivalente ao "Follow TCP Stream" do Wireshark em modo texto.
  for stream in $streams; do
    content="$(tshark -r "$PCAP_FILE" -q -z follow,tcp,ascii,"$stream" 2>/dev/null \
      | grep -Eai 'user|pass|password|login|token|secret|authorization|cookie|GET |POST |PUT |DELETE |USER |PASS |/bin/bash|bash -i|whoami|/etc/passwd|id_rsa|sudo|chmod|shell\.php|\.php|\.sh' \
      | head -40)"

    if [ -n "$content" ]; then
      warn "Suspicious text found in TCP stream $stream"
      echo "$content" | sed 's/^/  /'
    fi
  done
}

###############################################################################
# 11. Resumo rápido de próximos passos
###############################################################################

next_steps() {
  section "11. Suggested manual follow-up"

  note "Useful commands after finding something interesting:"
  cat <<EOF | sed 's/^/  /'
# Show all packets with a display filter:
tshark -r "$PCAP_FILE" -Y 'http || ftp || dns'

# Follow a specific TCP stream:
tshark -r "$PCAP_FILE" -q -z follow,tcp,ascii,STREAM_ID

# List all TCP stream IDs:
tshark -r "$PCAP_FILE" -T fields -e tcp.stream | sort -n | uniq

# Extract HTTP objects, if present:
mkdir -p extracted_http
tshark -r "$PCAP_FILE" --export-objects http,extracted_http

# Quick brute text triage:
strings "$PCAP_FILE" | grep -Ei 'user|pass|token|secret|shell|/home|/var/www|/etc/passwd'
EOF
}

###############################################################################
# Execução principal
###############################################################################

print_banner
check_dependencies
basic_file_info
protocol_summary
conversation_summary
http_analysis
ftp_analysis
dns_analysis
cleartext_protocols_analysis
strings_analysis
stream_analysis
next_steps

printf "\n%b\n" "${BLUE}Done.${NC} Review [CRITICAL] and [HIGH] findings first."
