#Requires -Version 7.0
<#
.SYNOPSIS
    Aplica ofuscação .NET nos assemblies publicados antes de empacotar.

.DESCRIPTION
    ESTADO ATUAL: scaffolding — não funcional sem PublishSingleFile=false.

    LIMITAÇÃO TÉCNICA:
    Com PublishSingleFile=true (BUILD.bat atual), todos os assemblies ficam
    dentro de um único EXE bundle. Ferramentas de ofuscação como Obfuscar e
    ConfuserEx operam sobre DLLs individuais e não podem processar o bundle
    diretamente.

    CAMINHO PARA IMPLEMENTAÇÃO (próximo sprint):
    1. Alterar BUILD.bat para publicar SEM PublishSingleFile em uma pasta
       intermediária (publish\win-x64-raw\).
    2. Executar este script sobre a pasta intermediária.
    3. Reempacotar os arquivos ofuscados como bundle ou distribuir como pasta.

    TOOL RECOMENDADA: Obfuscar (open-source, .NET 8 compatível)
      dotnet tool install -g Obfuscar.GlobalTool
      obfuscar.console obfuscar.xml

    EXCLUSÕES OBRIGATÓRIAS (não ofuscar para não quebrar a GUI e reports):
    - ViewModels públicos (WPF XAML bindings por nome)
    - Propriedades [ObservableProperty] / comandos [RelayCommand]
    - Tipos usados por JsonSerializer (nomes serializados)
    - Métodos P/Invoke e tipos com [StructLayout]
    - Tipos em namespace EchoNerfados.App (GUI — WPF depende de reflection)

    FEATURES A CONFIGURAR:
    - Renaming (classes/métodos internos) — SAFE para types não-públicos
    - String Encryption — SAFE
    - Control Flow Obfuscation — SAFE
    - Anti-tamper — SAFE
    - Resource Encryption — TESTAR (pode quebrar resources WPF)

    CONFIG DE REFERÊNCIA (obfuscar.xml):
    <?xml version='1.0'?>
    <Obfuscator>
      <Var name="InPath"  value="publish\win-x64-raw" />
      <Var name="OutPath" value="publish\win-x64-obf" />
      <Module file="$(InPath)\EchoNerfados.Core.dll">
        <SkipType name="*ViewModel" />
        <SkipType name="*Dto" />
        <SkipType name="*ExportDto" />
        <SkipNamespace name="EchoNerfados.App" />
      </Module>
    </Obfuscator>

.NOTES
    Este script está reservado para o sprint de ofuscação.
    Não executar na pipeline atual (PublishSingleFile=true).
#>
param()

Write-Host ""
Write-Host "=======================================================" -ForegroundColor Yellow
Write-Host " Obfuscation — NÃO IMPLEMENTADO AINDA" -ForegroundColor Yellow
Write-Host "=======================================================" -ForegroundColor Yellow
Write-Host ""
Write-Host " MOTIVO: PublishSingleFile=true embute todos os assemblies" -ForegroundColor Gray
Write-Host " no EXE principal. Ferramentas de ofuscação precisam de DLLs" -ForegroundColor Gray
Write-Host " separadas para operar." -ForegroundColor Gray
Write-Host ""
Write-Host " PRÓXIMO SPRINT:" -ForegroundColor Gray
Write-Host "   1. Publish sem PublishSingleFile em pasta intermediária" -ForegroundColor Gray
Write-Host "   2. Obfuscar com Obfuscar ou ConfuserEx" -ForegroundColor Gray
Write-Host "   3. Reempacotar para distribuição" -ForegroundColor Gray
Write-Host ""
Write-Host " RISCO ACEITO PARA BUILD DE TESTE:" -ForegroundColor Yellow
Write-Host "   Assemblies distribuídos sem ofuscação nesta fase." -ForegroundColor Yellow
Write-Host "   Ativar antes da versão comercial." -ForegroundColor Yellow
Write-Host ""
exit 0
