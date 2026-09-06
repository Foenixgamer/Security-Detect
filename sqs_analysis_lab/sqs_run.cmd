@echo off
REM sqs_run.cmd - Lanzador de doble clic para el laboratorio aislado SQS
REM Abre resultados en: C:\AI-Security\sqs_analysis_lab\salidas
title SQS - Laboratorio Aislado (demo educativa)
chcp 65001 >nul
echo ============================================================
echo  SQS - Sanitizador Quirurgico de Software
echo  Demo educativa aislada (carpeta que no se propaga por la PC)
echo ============================================================
echo.
echo [1/2] Analizando muestras...
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0ejecutar_prueba.ps1"
echo.
echo [2/2] Fin del analisis.
echo Resultados en: %~dp0salidas
echo Resume (summary_report.json) en: %~dp0salidas\summary_report.json
echo.
pause