@echo off
REM ============================================================
REM Echo Nerfados Shield XDR - Build QA (alias para BUILD-RC)
REM ============================================================
REM
REM O sistema de licença está desabilitado para a fase de testes
REM (LicenseValidator.EnforceLicense = false). O scanner executa
REM normalmente sem license.nerf em qualquer máquina.
REM
REM BUILD-QA.bat é temporariamente um alias de BUILD-RC.bat.
REM Quando o fluxo comercial for ativado (EnforceLicense = true),
REM este script voltará a gerar licença wildcard embutida.
REM
REM USAGE:
REM   BUILD-QA.bat [--sign]
REM ============================================================
call BUILD-RC.bat %*
