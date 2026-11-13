<#
  Instalador do Padme para Windows.

  Jeito facil: de dois cliques em install.bat (na mesma pasta deste arquivo).
  Pelo PowerShell:   powershell -ExecutionPolicy Bypass -File install.ps1
  Sem baixar nada:   irm https://raw.githubusercontent.com/LuizWT/PADME/main/install.ps1 | iex
  Remover:           install.bat -Uninstall   (mantem config e banco)
                     ou: $env:PADME_UNINSTALL=1; irm <mesmo endereco> | iex

  O que faz: acha o Python 3.10+ (ou instala pelo winget, se voce aceitar),
  cria um ambiente isolado em %LOCALAPPDATA%\padme, instala o Padme nele, cria
  o comando `padme` e o coloca no PATH do seu usuario, e roda o `padme init`
  se ainda nao houver config. Nao precisa de administrador.

  Este arquivo e so ASCII de proposito (por isso as mensagens sem acento): com
  acentos ele precisaria de BOM, que atrapalha o modo "irm ... | iex".
#>
param([switch]$Uninstall)

$ErrorActionPreference = 'Stop'
# modo "irm | iex" nao aceita -Uninstall: vem pela variavel, usada uma vez so
if ($env:PADME_UNINSTALL) { $Uninstall = $true; Remove-Item Env:PADME_UNINSTALL }
$Repo = 'LuizWT/PADME'
$Ref = if ($env:PADME_REF) { $env:PADME_REF } else { 'main' }
$DefaultHome = Join-Path $env:LOCALAPPDATA 'padme'
$AppHome = if ($env:PADME_HOME) { $env:PADME_HOME } else { $DefaultHome }
$Venv = Join-Path $AppHome 'venv'
$Bin = Join-Path $AppHome 'bin'
$VenvPy = Join-Path $Venv 'Scripts\python.exe'
$Shim = Join-Path $Bin 'padme.cmd'

function Say([string]$Msg) { Write-Host $Msg }
function Fail([string]$Msg) {
    Write-Host "`nERRO: $Msg" -ForegroundColor Red
    # rodando de um arquivo (install.bat): sai com erro. Pelo "irm | iex" o
    # script roda dentro do PowerShell do usuario, e um exit fecharia a janela.
    if ($PSCommandPath) { exit 1 }
    throw 'Instalacao interrompida.'
}

# PATH do usuario direto no registro, sem expandir %VARIAVEIS% de outras
# entradas (o SetEnvironmentVariable expandiria e gravaria tudo literal).
function Get-UserPath {
    $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Environment')
    $raw = $key.GetValue('Path', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
    $key.Close()
    return [string]$raw
}

function Set-UserPath([string]$Value) {
    $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Environment', $true)
    $key.SetValue('Path', $Value, [Microsoft.Win32.RegistryValueKind]::ExpandString)
    $key.Close()
    # avisa o Windows da mudanca (terminais novos ja enxergam o PATH novo)
    [Environment]::SetEnvironmentVariable('PADME_PATH_REFRESH', '1', 'User')
    [Environment]::SetEnvironmentVariable('PADME_PATH_REFRESH', $null, 'User')
}

if ($Uninstall) {
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $Venv, $Bin
    $parts = @((Get-UserPath) -split ';' | Where-Object { $_ -and ($_.TrimEnd('\') -ne $Bin.TrimEnd('\')) })
    Set-UserPath ($parts -join ';')
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $AppHome
    Say "Padme removido. Config e banco continuam em $env:APPDATA\padme"
    Say '(apague essa pasta se nao quiser mais os dados).'
    return
}

Say '== Instalando o Padme =='

# 1) Python 3.10 ou mais novo (o "python" falso da Microsoft Store nao conta)
function Test-Python($Exe, $Extra) {
    $old = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $out = & $Exe @Extra -c 'import sys; print(sys.version.split()[0]) if sys.version_info >= (3, 10) else sys.exit(1)' 2>$null
        return ($LASTEXITCODE -eq 0 -and $out)
    } catch {
        return $false
    } finally {
        $ErrorActionPreference = $old
    }
}

function Find-Python {
    foreach ($c in @(@{ Exe = 'py'; Extra = @('-3') }, @{ Exe = 'python'; Extra = @() }, @{ Exe = 'python3'; Extra = @() })) {
        if ((Get-Command $c.Exe -ErrorAction SilentlyContinue) -and (Test-Python $c.Exe $c.Extra)) {
            return $c
        }
    }
    return $null
}

$Py = Find-Python
if (-not $Py) {
    Say 'Nao achei o Python 3.10 ou mais novo.'
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        $ans = Read-Host 'Instalar o Python 3.12 agora pelo winget (so para o seu usuario)? [S/n]'
        if ($ans -eq '' -or $ans -match '^[sSyY]') {
            winget install -e --id Python.Python.3.12 --scope user --accept-package-agreements --accept-source-agreements
            $env:Path = [Environment]::GetEnvironmentVariable('Path', 'Machine') + ';' + [Environment]::GetEnvironmentVariable('Path', 'User')
            $Py = Find-Python
        }
    }
    if (-not $Py) {
        Fail 'Instale o Python 3.10+ em https://www.python.org/downloads/ (marque "Add python.exe to PATH") e rode o instalador de novo.'
    }
}
$PyExtra = $Py.Extra
$PyVersion = & $Py.Exe @PyExtra -c 'import sys; print(sys.version.split()[0])'
Say "Python: $PyVersion ($($Py.Exe))"

# 2) de onde instalar: a pasta deste script (zip baixado ou clone) ou o GitHub
$Src = "https://github.com/$Repo/archive/$Ref.zip"
if ($PSScriptRoot) {
    $Toml = Join-Path $PSScriptRoot 'pyproject.toml'
    if ((Test-Path $Toml) -and (Select-String -Path $Toml -Pattern 'padme-asm' -Quiet)) { $Src = $PSScriptRoot }
}
if ($env:PADME_SRC) { $Src = $env:PADME_SRC }
Say "Origem: $Src"

# 3) ambiente isolado e instalacao
New-Item -ItemType Directory -Force -Path $AppHome | Out-Null
if (-not (Test-Path $VenvPy)) {
    & $Py.Exe @PyExtra -m venv $Venv
    if ($LASTEXITCODE -ne 0) { Fail "nao consegui criar o ambiente em $Venv" }
}
& $VenvPy -m pip install --quiet --disable-pip-version-check --upgrade pip
& $VenvPy -m pip install --quiet --disable-pip-version-check --upgrade $Src
if ($LASTEXITCODE -ne 0) { Fail 'a instalacao pelo pip falhou (veja a mensagem acima).' }

# 4) comando `padme`: um .cmd que chama o Python do ambiente (nada de "python padme").
#    Na pasta padrao usa %LOCALAPPDATA%, que funciona com acento no nome do usuario.
New-Item -ItemType Directory -Force -Path $Bin | Out-Null
$Target = if ($AppHome -eq $DefaultHome) { '%LOCALAPPDATA%\padme\venv\Scripts\python.exe' } else { $VenvPy }
$Lines = @('@echo off', 'setlocal', 'set PYTHONUTF8=1', "`"$Target`" -m padme %*")
[IO.File]::WriteAllText($Shim, (($Lines -join "`r`n") + "`r`n"), [Text.Encoding]::ASCII)

# 5) pasta do comando no PATH do usuario (terminais novos) e nesta sessao
$NewShell = $false
$Parts = @((Get-UserPath) -split ';' | Where-Object { $_ })
if (-not ($Parts | Where-Object { $_.TrimEnd('\') -eq $Bin.TrimEnd('\') })) {
    Set-UserPath ((@($Parts) + $Bin) -join ';')
    $NewShell = $true
}
if (-not (($env:Path -split ';') -contains $Bin)) { $env:Path = "$env:Path;$Bin" }

$Version = & $Shim --version
Say "Instalado: $Version"

# 6) config: se ainda nao existe, cria agora
$Config = & $VenvPy -c 'from padme.paths import find_config; print(find_config())'
if (Test-Path $Config) {
    Say "Config existente mantido: $Config"
} else {
    Say ''
    & $Shim init
    if ($LASTEXITCODE -ne 0) { Say 'Rode depois: padme init' }
}

Say ''
Say '== Pronto =='
if ($NewShell) { Say 'Abra um terminal NOVO (PowerShell ou Prompt de Comando) e digite:' } else { Say 'Digite:' }
Say '  padme              monitora e abre o painel em http://127.0.0.1:8787'
Say '  padme -h           todas as opcoes'
Say '  padme --update     atualiza para a versao mais recente'
