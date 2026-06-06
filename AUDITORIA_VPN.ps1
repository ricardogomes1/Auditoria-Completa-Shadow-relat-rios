# ==============================================================================
# MAIS AUDITORIA RDS V10.7 - PRODUCTION BLINDCORE (CLEAN NAMES Core)
# Windows Server 2019 / Optimized for WTS High-Load Environments (ASCII Clean)
# ==============================================================================

Add-Type -AssemblyName System.Web
Add-Type -AssemblyName Microsoft.VisualBasic

# --- DETECCAO DINAMICA DE USUARIO E PORTA DENTRO DO INTERVALO LIBERADO ---
$UsuarioAtual = [Environment]::UserName.ToLower()

# Mapeamento estrito conforme suas 5 portas liberadas
$TabelaPortas = @{
    "ricardo.gomes" = 5555
    "admin.infra"   = 6666
    "admin.suporte" = 8888
    "admin.ti"      = 4444
    "admin.gerencia"= 7777
}

if ($TabelaPortas.ContainsKey($UsuarioAtual)) {
    $PortAtalho = $TabelaPortas[$UsuarioAtual]
    if (-not (Get-NetTCPConnection -LocalPort $PortAtalho -State Listen -ErrorAction SilentlyContinue)) {
        $Port = $PortAtalho
    }
}

if ($null -eq $Port) {
    $PortasPermitidas = @(4444, 5555, 6666, 7777, 8888)
    foreach ($p in $PortasPermitidas) {
        if (-not (Get-NetTCPConnection -LocalPort $p -State Listen -ErrorAction SilentlyContinue)) {
            $Port = $p
            break
        }
    }
}

if ($null -eq $Port) {
    Write-Host "[ERRO FATAL] Todas as portas liberadas (4444, 5555, 6666, 7777, 8888) estao ocupadas!" -ForegroundColor Red
    Exit
}

$ServerIP = "10.180.0.3"

# Coleta de Metadados de Infraestrutura Geral do Servidor
$Global:TotalServerRAM = [Microsoft.VisualBasic.Devices.ComputerInfo]::new().TotalPhysicalMemory

# Controle de Relatorios CSV Isolados (Nome do arquivo leva o nome do Admin)
$PastaLocal = $PSScriptRoot
if ([string]::IsNullOrEmpty($PastaLocal)) { $PastaLocal = $env:USERPROFILE + "\Desktop" }
$Global:UltimoRelatorio = [DateTime]::UtcNow
$Global:HoraProximoRelatorioStr = (Get-Date).AddMinutes(10).ToString("HH:mm")

# --- INSTANCIACAO DOS BUFFERS GLOBAIS DE MEMORIA COMPARTILHADA ---
$Global:DashboardData = [hashtable]::Synchronized(@{
    timer    = (Get-Date).AddMinutes(10).ToString("HH:mm")
    stats    = @{ Total = 0; Ativos = 0; Ociosos = 0; Desconectados = 0 }
    sessions = @()
})

# Buffer de String JSON pré-serializado na RAM
$Global:DashboardCachedJsonStr = '{"timer":"--:--","stats":{"Total":0,"Ativos":0,"Ociosos":0,"Desconectados":0},"sessions":[]}'

# Timers Decompilados da Esteira de Coleta Assincrona
$Global:UltimoCheckQuser = [DateTime]::UtcNow.AddMinutes(-5) # 15s
$Global:UltimoCheckProcs = [DateTime]::UtcNow.AddMinutes(-5) # 60s

# Tabelas de Isolamento de Memoria de Fundo
$Global:LocalProcessMapCache = @{}
$Global:LocalRawSessions     = @()

function Convert-IdleToMinutes {
    param([string]$Idle)
    if ([string]::IsNullOrWhiteSpace($Idle) -or $Idle -eq ".") { return 0 }
    if ($Idle -match '^(\d+):(\d+)$') { return ([int]$Matches[1] * 60) + [int]$Matches[2] }
    if ($Idle -match '^\d+$') { return [int]$Idle }
    return 0
}

# PARSER INDESTRUTIVEL DO QUSER 
function Get-Sessions-Engine {
    $sessions = @()
    $raw = quser 2>$null
    if (-not $raw) { return $sessions }

    try {
        foreach ($line in ($raw | Select-Object -Skip 1)) {
            if ([string]::IsNullOrWhiteSpace($line)) { continue }

            $line = $line.TrimStart(">")
            $parts = ($line -replace '\s{2,}','|').Split('|')

            if ($parts.Count -eq 6) {
                $user       = $parts[0]
                $session    = $parts[1]
                $id         = $parts[2]
                $state      = $parts[3]
                $idle       = $parts[4]
            }
            elseif ($parts.Count -eq 5) {
                $user       = $parts[0]
                $session = ""
                $id         = $parts[1]
                $state      = $parts[2]
                $idle       = $parts[3]
            }
            else { continue }

            if ($id -notmatch '^\d+$') { continue }

            $sessions += [PSCustomObject]@{
                User        = $user
                SessionName = $session
                Id          = [int]$id
                State       = $state
                IdleTime    = $idle
                IdleMinutes = Convert-IdleToMinutes $idle
            }
        }
    }
    catch {
        Add-Content -Path "$env:TEMP\mais_auditoria_error.log" -Value "$(Get-Date) Erro Parser quser: $($_.Exception.Message)"
    }
    return $sessions
}

# THREAD DE TELEMETRIA DESACOPLADA
function Update-EnterpriseTelemetryCache {
    try {
        $Agora = [DateTime]::UtcNow
        $HouveMudanca = $false

        # ESTEIRA 1: Sessoes RDS via Parser Blindado (A cada 15 segundos)
        if (($Agora - $Global:UltimoCheckQuser).TotalSeconds -gt 15 -or $Global:LocalRawSessions.Count -eq 0) {
            $Global:LocalRawSessions = Get-Sessions-Engine
            $Global:UltimoCheckQuser = $Agora
            $HouveMudanca = $true
        }

        # ESTEIRA 2: Recursos de Processos via Win32_Process CIM (A cada 60 segundos)
        if (($Agora - $Global:UltimoCheckProcs).TotalSeconds -gt 60 -or $Global:LocalProcessMapCache.Count -eq 0) {
            
            $allProcesses = Get-CimInstance -ClassName Win32_Process -Filter "SessionId > 0" -ErrorAction SilentlyContinue | 
                            Select-Object ProcessId, SessionId, HandleCount, WorkingSetSize

            $localProcessMap = @{}
            foreach ($p in $allProcesses) {
                if ($null -ne $p.SessionId) {
                    $sid = [string]$p.SessionId
                    if (-not $localProcessMap.ContainsKey($sid)) {
                        $localProcessMap[$sid] = @{ Handles = 0; Processos = 0; WorkingSet = 0 }
                    }
                    $localProcessMap[$sid].Handles    += $p.HandleCount
                    $localProcessMap[$sid].Processos++
                    $localProcessMap[$sid].WorkingSet  += $p.WorkingSetSize
                }
            }

            $Global:LocalProcessMapCache = $localProcessMap
            $Global:UltimoCheckProcs = $Agora
            $HouveMudanca = $true
        }

        if ($HouveMudanca -and $Global:LocalRawSessions.Count -gt 0) {
            $sortedSessions = $Global:LocalRawSessions | Sort-Object `
                @{Expression={$_.State -match "Disc|Disco|Sep|Disconnected"}; Descending=$false},
                @{Expression={$_.IdleMinutes -gt 5}; Descending=$false},
                @{Expression={$_.IdleMinutes}; Descending=$false}

            $tUsers = $sortedSessions.Count
            $tAtivos = 0; $tOciosos = 0; $tDesc = 0
            
            foreach ($s in $sortedSessions) {
                if ($s.State -match 'Disc|Disco') { $tDesc++ }
                elseif ($s.IdleMinutes -gt 5) { $tOciosos++ }
                else { $tAtivos++ }
            }

            $enrichedPayload = @()
            foreach ($s in $sortedSessions) {
                $sidKey = [string]$s.Id
                $handles = 0; $processCount = 0; $ramMB = 0
                
                if ($Global:LocalProcessMapCache.ContainsKey($sidKey)) {
                    $handles      = $Global:LocalProcessMapCache[$sidKey].Handles
                    $processCount = $Global:LocalProcessMapCache[$sidKey].Processos
                    $ramMB        = $Global:LocalProcessMapCache[$sidKey].WorkingSet
                }

                # AJUSTE CORPORATIVO SOLICITADO: Tags de texto [O] e [D] removidas para deixar os nomes limpos
                if ($s.State -match 'Disc|Disco') {
                    $statusVisual = 'DESCONECTADO'; $color = "#ef4444"; $borderClass = "card-desconectado"; $ico = ""
                }
                elseif ($s.IdleMinutes -gt 5) {
                    $statusVisual = 'OCIOSO'; $color = "#f59e0b"; $borderClass = "card-ocioso"; $ico = ""
                }
                else {
                    $statusVisual = 'ATIVO'; $color = "#22c55e"; $borderClass = "card-ativo"; $ico = ""
                }

                $pctRam = [math]::Min([math]::Round(($ramMB / $Global:TotalServerRAM) * 100, 1), 100)
                $ramFormatted = [math]::Round($ramMB / 1MB)

                $item = [ordered]@{
                    id              = [int]$s.Id
                    usuario         = [string]$s.User
                    sessao          = [string]$s.SessionName
                    estado          = [string]$s.State
                    statusvisual    = [string]$statusVisual
                    color           = [string]$color
                    borderclass     = [string]$borderClass
                    ico             = [string]$ico
                    tempoocioso     = [string]$s.IdleTime
                    handles         = [string]("{0:N0}" -f $handles)
                    processoscontar = [int]$processCount
                    rammb           = [string]("{0:N0}" -f $ramFormatted)
                    pctram          = [float]$pctRam
                }
                $enrichedPayload += $item
            }

            $Global:DashboardData.stats    = @{ Total = $tUsers; Ativos = $tAtivos; Ociosos = $tOciosos; Desconectados = $tDesc }
            $Global:DashboardData.sessions = $enrichedPayload
            $Global:DashboardData.timer    = $Global:HoraProximoRelatorioStr

            $Global:DashboardCachedJsonStr = ConvertTo-Json -InputObject $Global:DashboardData -Depth 5
        }
    }
    catch {
        Add-Content -Path "$env:TEMP\mais_auditoria_error.log" -Value "$(Get-Date) Erro no loop de telemetria: $($_.Exception.Message)"
    }
}

# --- TEMPLATE INTERFACE GRAPHICA SPA REATIVO PREMIUM ---
$RawHtmlPage = @"
<!DOCTYPE html>
<html>
<head>
<meta charset='utf-8'>
<title>Mais Auditoria RDS V10.7 Stable</title>
<style>
body { margin:0; font-family:'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background:#0b1220; color:#e5e7eb; }
.header { padding:16px 24px; background:#111827; color:#60a5fa; font-weight:700; font-size:18px; border-bottom: 1px solid #1f2937; display: flex; justify-content: space-between; align-items: center; }
.timer-badge { background:#1e293b; color:#9ca3af; font-size:12px; padding:6px 12px; border-radius:6px; border: 1px solid #334155; }
.top-bar-controls { display:flex; gap:20px; align-items:center; padding:15px 24px 5px 24px; }
.search-input { background:#111827; border:1px solid #1f2937; border-radius:8px; padding:10px 16px; color:#e5e7eb; font-size:14px; width:300px; outline:none; transition: border-color 0.2s; }
.search-input:focus { border-color:#2563eb; }
.stats { display:flex; gap:15px; padding:10px 24px 10px 24px; width: calc(100% - 48px); }
.stat { background:#111827; border:1px solid #1f2937; border-radius:12px; padding:15px; min-width:160px; display:flex; flex-direction:column; flex:1; }
.stat span { font-size:12px; color:#9ca3af; font-weight:500; }
.stat b { font-size:24px; margin-top:4px; }
.grid { padding:10px 24px 24px 24px; display:grid; grid-template-columns:repeat(auto-fill,minmax(280px,1fr)); gap:14px; }
.card { background:#111827; border:1px solid #1f2937; border-radius:14px; padding:14px; display:flex; flex-direction:column; transition:transform 0.2s,box-shadow 0.2s; }
.card:hover { transform:translateY(-2px); box-shadow:0 4px 12px rgba(0,0,0,0.3); }
.card-ativo { border-top:4px solid #22c55e; }
.card-ocioso { border-top:4px solid #f59e0b; }
.card-desconectado { border-top:4px solid #ef4444; }
.user { font-size:16px; font-weight:600; margin-bottom:6px; border-bottom: 1px solid #1f2937; padding-bottom:6px; }
.box-container-double { display:flex; gap:8px; width:100%; }
.box-container-double .box { flex:1; }
.box { margin-top:8px; padding:8px; background:#0f172a; border-radius:8px; font-size:12px; }
.progress { background:#1f2937; border-radius:4px; height:6px; margin-top:6px; overflow:hidden; width:100%; }
.progress-fill { background:#2563eb; height:100%; width:0%; transition: width 0.4s ease; }
.btn-shadow { display:block; margin-top:14px; padding:10px 12px; background:#2563eb; color:white; text-decoration:none; border-radius:8px; font-size:13px; font-weight:600; text-align:center; cursor:pointer; border:none; width:100%; transition:background 0.2s; }
.btn-shadow:hover { background:#1d4ed8; }
.btn-shadow:disabled { background:#334155 !important; color:#64748b !important; cursor:not-allowed !important; opacity:0.6; }
</style>
</head>
<body>
    <div class='header'>
        <div id='lblTitle'>MAIS AUDITORIA RDS V10.7</div>
        <div class='timer-badge' id='lblCsv'>Horario do proximo relatorio CSV: --:--</div>
    </div>

    <div class='top-bar-controls'>
        <input type='text' id='searchUser' class='search-input' placeholder='Filtrar utilizador por nome...' oninput='filtrarCards()'>
    </div>

    <div class='stats'>
        <div class='stat' style='border-left:4px solid #60a5fa;'><span>Utilizadores Totais</span><b id='stTotal'>0</b></div>
        <div class='stat' style='border-left:4px solid #22c55e;'><span>Sessoes Ativas</span><b id='stAtivos'>0</b></div>
        <div class='stat' style='border-left:4px solid #f59e0b;'><span>Sessoes Ociosas</span><b id='stOciosos'>0</b></div>
        <div class='stat' style='border-left:4px solid #ef4444;'><span>Desconectados</span><b id='stDesc'>0</b></div>
    </div>

    <div class='grid' id='cardGrid'></div>

<script>
    let atualizando = false;
    var currentPort = window.location.port || "5555";
    document.getElementById('lblTitle').innerText = 'MAIS AUDITORIA RDS V10.7 (PORTA ' + currentPort + ')';

    function filtrarCards() {
        var filtro = document.getElementById('searchUser').value.toLowerCase();
        var cards = document.querySelectorAll('.card');
        for (var i = 0; i < cards.length; i++) {
            var nome = cards[i].getAttribute('data-user').toLowerCase();
            cards[i].style.display = (nome.indexOf(filtro) > -1) ? 'flex' : 'none';
        }
    }

    // Chamada AJAX Fetch otimizada livre de JQuery/XHR antigo
    function dispararShadow(id) {
        fetch('/acessar/' + id)
            .then(res => res.text())
            .then(txt => console.log('Shadow alocado.'))
            .catch(err => console.warn('Erro shadow.'));
    }

    function SincronizarPainelAPI() {
        if (atualizando) return;
        atualizando = true;

        fetch('/api/dashboard')
            .then(res => res.json())
            .then(data => {
                document.getElementById('lblCsv').innerText = 'Horario do proximo relatorio CSV: ' + data.timer;
                document.getElementById('stTotal').innerText = data.stats.Total;
                document.getElementById('stAtivos').innerText = data.stats.Ativos;
                document.getElementById('stOciosos').innerText = data.stats.Ociosos;
                document.getElementById('stDesc').innerText = data.stats.Desconectados;

                var grid = document.getElementById('cardGrid');
                var list = data.sessions;
                if (list && !Array.isArray(list)) { list = [list]; }
                
                if (!list || list.length === 0) { grid.innerHTML = ''; return; }

                list.forEach(s => {
                    var cardId = 'card-session-' + s.id;
                    var card = document.getElementById(cardId);

                    // Sanitizacao nativa limpa eliminando os prefixos textuais [O] e [D] solicitados
                    var userHeaderDisplay = s.ico ? (s.ico + " " + s.usuario) : s.usuario;
                    var isDisabledStr = (s.borderclass === "card-desconectado") ? "disabled" : "";

                    if (!card) {
                        var div = document.createElement('div');
                        div.id = cardId;
                        div.className = 'card ' + s.borderclass;
                        div.setAttribute('data-user', s.usuario);
                        div.innerHTML = "<div class='user'><span class='txt-user'>" + userHeaderDisplay + "</span><br><span class='txt-status' style='color:" + s.color + "; font-size:12px;'>[" + s.statusvisual + "]</span></div>" +
                            "<div class='box-container-double'>" +
                                "<div class='box'>Sessao: <b>" + s.id + "</b></div>" +
                                "<div class='box'>Ociosidade: <b class='txt-idle'>" + s.tempoocioso + "</b></div>" +
                            "</div>" +
                            "<div class='box-container-double'>" +
                                "<div class='box'>Handles: <b class='txt-handles'>" + s.handles + "</b></div>" +
                                "<div class='box'>Processos: <b class='txt-procs'>" + s.processoscontar + "</b></div>" +
                            "</div>" +
                            "<div class='box-container-double'>" +
                                "<div class='box'>" +
                                    "RAM: <b class='txt-ram'>" + s.rammb + " MB</b>" +
                                    "<div class='progress'><div class='progress-fill fill-ram' style='width:" + s.pctram + "%'></div></div>" +
                                "</div>" +
                            "</div>" +
                            "<button class='btn-shadow' " + isDisabledStr + " onclick='dispararShadow(" + s.id + ")'>Acessar</button>";
                        grid.appendChild(div);
                    } else {
                        card.className = 'card ' + s.borderclass;
                        card.setAttribute('data-user', s.usuario);
                        card.querySelector('.txt-user').innerText = userHeaderDisplay;
                        var stSpan = card.querySelector('.txt-status');
                        stSpan.innerText = '[' + s.statusvisual + ']';
                        stSpan.style.color = s.color;

                        card.querySelector('.txt-idle').innerText = s.tempoocioso;
                        card.querySelector('.txt-handles').innerText = s.handles;
                        card.querySelector('.txt-procs').innerText = s.processoscontar;
                        card.querySelector('.txt-ram').innerText = s.rammb + ' MB';
                        card.querySelector('.fill-ram').style.width = s.pctram + '%';
                        
                        var btn = card.querySelector('.btn-shadow');
                        if (s.borderclass === "card-desconectado") {
                            btn.setAttribute('disabled', 'disabled');
                        } else {
                            btn.removeAttribute('disabled');
                        }
                    }
                });

                var currentCards = grid.querySelectorAll('.card');
                currentCards.forEach(c => {
                    var cid = parseInt(c.id.replace('card-session-', ''));
                    var existe = list.some(s => s.id === cid);
                    if (!existe) { c.remove(); }
                });
                filtrarCards();
            })
            .catch(err => console.warn('Erro ao ler API.'))
            .finally(() => {
                atualizando = false;
            });
    }

    SincronizarPainelAPI();
    setInterval(SincronizarPainelAPI, 10000);
</script>
</body>
</html>
"@

$Global:HtmlTemplateBuffer = [System.Text.Encoding]::UTF8.GetBytes($RawHtmlPage)

# Inicializacao Base do HTTP Listener do Windows Server
$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Add("http://+:$Port/")
try { 
    $listener.Start() 
} catch { 
    Write-Host "[ERRO CRITICO V10.7] Falha fatal de bind na porta $Port." -ForegroundColor Red
    exit 
}

Write-Host "SUCESSO DE IMPLANTACAO! INSTANCIA DO USUARIO [$UsuarioAtual] ATIVA NA PORTA $Port" -ForegroundColor Green

# Primeira carga obrigatoria no arranque
Update-EnterpriseTelemetryCache
$Global:UltimoCheckEsteiraCompleta = [DateTime]::UtcNow

while ($listener.IsListening) {
    try {
        $TickAgora = [DateTime]::UtcNow
        if (($TickAgora - $Global:UltimoCheckEsteiraCompleta).TotalSeconds -gt 5) {
            Update-EnterpriseTelemetryCache
            $Global:UltimoCheckEsteiraCompleta = $TickAgora
        }

        # 1. Rotina de Dump de Relatorios CSV Isolados por Administrador (A cada 10 minutos)
        $AgoraUTC = [DateTime]::UtcNow
        $TempoDecorrido = ($AgoraUTC - $Global:UltimoRelatorio).TotalMinutes
        $TempoRestante = [Math]::Round(10 - $TempoDecorrido, 1)
        if ($TempoRestante -lt 0) { $TempoRestante = 0 }
        $Global:HoraProximoRelatorioStr = (Get-Date).AddMinutes($TempoRestante).ToString("HH:mm")

        if ($TempoDecorrido -ge 10) {
            $snapSessions = $Global:DashboardData.sessions
            if ($snapSessions -and $snapSessions.Count -gt 0) {
                $TimeStamp = Get-Date -Format "yyyy-MM-dd_HH-mm"
                $CaminhoRelatorio = Join-Path $PastaLocal "Relatorio_MaisAuditoria_${UsuarioAtual}_$TimeStamp.csv"
                $snapSessions | ForEach-Object { [PSCustomObject]$_ } | Export-Csv -Path $CaminhoRelatorio -NoTypeInformation -Delimiter ";" -Encoding UTF8 -Force
            }
            $Global:UltimoRelatorio = $AgoraUTC
        }

        if (-not $listener.IsListening) { break }
        $ctx = $listener.GetContext()
        
        $req = $ctx.Request
        $res = $ctx.Response

        if ($req.HttpMethod -eq "OPTIONS") {
            $res.StatusCode = 200
            $res.Headers.Add("Access-Control-Allow-Origin", "*")
            $res.Headers.Add("Access-Control-Allow-Methods", "GET, OPTIONS")
            $res.Headers.Add("Access-Control-Allow-Headers", "Content-Type")
            $res.Close()
            continue
        }

        $res.KeepAlive = $false
        $res.Headers.Add("Connection", "close")
        $res.Headers.Add("Access-Control-Allow-Origin", "*")
        $res.Headers.Add("Cache-Control", "no-cache, no-store, must-revalidate")

        # INSTANCIA INDEPENDENTE DE SHADOW INTERNO POR USUARIO RDP
        if ($req.Url.AbsolutePath.StartsWith("/acessar/")) {
            $clientIP = $req.RemoteEndPoint.Address.ToString()
            if ($clientIP -notmatch '^10\.' -and $clientIP -ne "127.0.0.1" -and $clientIP -ne "::1") {
                $res.StatusCode = 403; $res.Close(); continue
            }

            $sessionIdStr = $req.Url.AbsolutePath.Split('/')[-1]
            $sessionId = [int]$sessionIdStr
            
            $idExiste = $false
            foreach ($sess in $Global:DashboardData.sessions) {
                if ($sess.id -eq $sessionId) { $idExiste = $true; break }
            }

            if ($idExiste) {
                try {
                    Add-Content -Path "$env:TEMP\mais_auditoria.log" -Value "$(Get-Date) [$UsuarioAtual] Shadow solicitado para $sessionId pelo Admin IP $clientIP"
                    
                    $ActiveAdminSessionId = (Get-Process -Name "explorer" -IncludeUserName | Where-Object { $_.UserName -match $UsuarioAtual } | Select-Object -First 1).SessionId
                    if ($null -eq $ActiveAdminSessionId) { $ActiveAdminSessionId = (Get-Process -Name "explorer" -ErrorAction SilentlyContinue | Select-Object -First 1).SessionId }

                    if ($null -ne $ActiveAdminSessionId) {
                        Start-Process -FilePath "$env:SystemRoot\System32\mstsc.exe" -ArgumentList "/shadow:$sessionId /control /v:$ServerIP /noConsentPrompt" -WindowStyle Normal
                    }
                } catch {
                    Add-Content -Path "$env:TEMP\mais_auditoria_error.log" -Value "$(Get-Date) [ERRO SHADOW] Falha: $($_.Exception.Message)"
                }
            }

            $res.StatusCode = 200
            $msgBuffer = [System.Text.Encoding]::UTF8.GetBytes("OK")
            $res.ContentLength64 = $msgBuffer.Length
            $res.OutputStream.Write($msgBuffer, 0, $msgBuffer.Length)
            $res.Close()
            continue
        }

        # ENDPOINT REST JSON API
        if ($req.Url.AbsolutePath -eq "/api/dashboard") {
            $bufferJson = [System.Text.Encoding]::UTF8.GetBytes($Global:DashboardCachedJsonStr)
            $res.ContentType = "application/json; charset=utf-8"
            $res.ContentLength64 = $bufferJson.Length
            $res.OutputStream.Write($bufferJson, 0, $bufferJson.Length)
            $res.Close()
            continue
        }

        # Retorno estavel do buffer do HTML
        $res.ContentType = "text/html; charset=utf-8"
        $res.ContentLength64 = $Global:HtmlTemplateBuffer.Length
        $res.OutputStream.Write($Global:HtmlTemplateBuffer, 0, $Global:HtmlTemplateBuffer.Length)
        $res.Close()
    }
    catch {
        Add-Content -Path "$env:TEMP\mais_auditoria_error.log" -Value "$(Get-Date) Erro Loop Principal HTTP: $($_.Exception.Message)"
    }
}

$listener.Stop()