# SQS - Prueba aislada del pipeline de 7 capas sobre muestras EDUCATIVAS.
# Todo el trabajo ocurre dentro de este directorio (muestras/ y salidas/):
# nada sale de aqui. Ninguna muestra ejecuta codigo real.
$ErrorActionPreference = "Stop"

$root  = $PSScriptRoot
$py    = Join-Path $env:LOCALAPPDATA "Programs\Python\Python312\python.exe"
$sqs   = "C:\AI-Security\sqsp\sqs.py"
$muestras = Join-Path $root "muestras"
$salidas  = Join-Path $root "salidas"

if (-not (Test-Path $py)) { $py = "python" }

Write-Host "=============================================="
Write-Host " SQS - Laboratorio aislado (demo educativa)"
Write-Host "=============================================="

if (-not (Test-Path (Join-Path $muestras "game_crack.exe"))) {
    Write-Host "[1/4] Generando muestras educativas..."
    & $py (Join-Path $root "generar_muestras.py") $muestras
} else {
    Write-Host "[1/4] Muestras ya generadas (educativas, 100% inertes)."
}

New-Item -ItemType Directory -Force -Path $salidas | Out-Null

Write-Host "[2/4] Pipeline SQS por muestra (veredicto -> cuarentena -> limpio)"
Write-Host ""
foreach ($sample in Get-ChildItem $muestras -File | Sort-Object Name) {
    Write-Host ("==== " + $sample.Name + " ====")
    & $py $sqs $sample.FullName -o $salidas
    Write-Host ""
}

$packages = Get-ChildItem (Join-Path $salidas "final_package_*") -Directory -ErrorAction SilentlyContinue
if ($packages) {
    Write-Host "[3/4] Paquetes finales (limpios y utilizables):"
    $packages | ForEach-Object {
        $kids = Get-ChildItem $_.FullName | ForEach-Object { $_.Name }
        Write-Host ("  - " + $_.Name + " => " + ($kids -join ", "))
    }
} else {
    Write-Host "[3/4] No se generaron paquetes. Revisa mensajes anteriores."
}

Write-Host ""
Write-Host "[4/4] Verificación automática de resultados"
& $py (Join-Path $root "auto_verify.py") $salidas
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host ""
Write-Host "Analisis completado."
Write-Host ("Resultados en: " + $salidas)