#!/usr/bin/env node
// build.js — gera index.html (site criptografado) e apresentacao.html (versão impressão/PDF)
// ARQUIVO PRIVADO — não distribuir. Manter junto com o source.
// Senha: nf3606 | Algoritmo: AES-256-GCM + PBKDF2-SHA256 (100.000 iterações)
'use strict';
const crypto = require('crypto');
const fs     = require('fs');
const path   = require('path');

const PASSWORD   = 'nf3606';
const ITERATIONS = 100_000;
const OUT_DIR    = __dirname;

// ─────────────────────────────────────────────────────────────────────────────
//  CONTEÚDO DA APRESENTAÇÃO (será encriptado)
// ─────────────────────────────────────────────────────────────────────────────
const PRESENTATION = `<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Echo Nerfados Shield XDR</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600;700&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
:root{
  --bg:#0A0E27;--bg2:#131829;--bg3:#1e2440;--bg4:#252c47;
  --cy:#00D9FF;--cy2:rgba(0,217,255,.12);--cy3:rgba(0,217,255,.25);
  --tx:#E8EAED;--tx2:#9fa6bc;--tx3:#6b748c;
  --red:#FF4D4D;--grn:#00FF88;--yel:#FFD600;--org:#FF8C00;
  --brd:rgba(0,217,255,.18);
  --mono:'IBM Plex Mono','Courier New',monospace;
  --sans:'Inter',-apple-system,'Segoe UI',sans-serif;
  --r:8px;--r2:14px;
}
*{box-sizing:border-box;margin:0;padding:0}
html{scroll-behavior:smooth}
body{background:var(--bg);color:var(--tx);font-family:var(--sans);font-size:15px;line-height:1.7}
h1,h2,h3,h4{font-family:var(--mono);font-weight:600;letter-spacing:-.5px}
a{color:var(--cy);text-decoration:none}

/* NAV */
nav{position:sticky;top:0;z-index:100;background:rgba(10,14,39,.92);backdrop-filter:blur(12px);
  border-bottom:1px solid var(--brd);padding:0 24px;display:flex;align-items:center;
  justify-content:space-between;height:60px}
.nav-brand{display:flex;align-items:center;gap:10px;font-family:var(--mono);font-weight:700;
  font-size:1rem;color:var(--cy)}
.nav-brand svg{flex-shrink:0}
.nav-links{display:flex;gap:4px;flex-wrap:wrap}
.nav-links a{padding:5px 11px;border-radius:6px;font-size:.82rem;color:var(--tx2);
  transition:all .18s}
.nav-links a:hover{background:var(--cy2);color:var(--cy)}
.nav-print{padding:6px 16px;border-radius:6px;background:var(--cy2);border:1px solid var(--brd);
  color:var(--cy);font-size:.82rem;font-family:var(--mono);cursor:pointer;transition:all .18s}
.nav-print:hover{background:var(--cy3)}

/* SECTIONS */
section{padding:80px 24px;max-width:1120px;margin:0 auto}
.section-tag{font-family:var(--mono);font-size:.72rem;color:var(--cy);letter-spacing:2px;
  text-transform:uppercase;margin-bottom:12px;opacity:.8}
.section-title{font-size:2rem;margin-bottom:10px;line-height:1.25}
.section-sub{color:var(--tx2);max-width:620px;margin-bottom:48px;font-size:.95rem}

/* HERO */
#hero{padding:100px 24px 80px;text-align:center;max-width:900px;position:relative}
.hero-wrap{display:flex;flex-direction:column;align-items:center;gap:28px}
.hero-badge{display:inline-flex;align-items:center;gap:8px;padding:6px 16px;
  border:1px solid var(--brd);border-radius:999px;font-size:.78rem;font-family:var(--mono);
  color:var(--cy);background:var(--cy2);margin-bottom:8px}
.hero-title{font-size:clamp(2.2rem,5vw,3.6rem);line-height:1.1;
  background:linear-gradient(135deg,#fff 30%,var(--cy));-webkit-background-clip:text;
  -webkit-text-fill-color:transparent;background-clip:text}
.hero-sub{font-size:1.1rem;color:var(--tx2);max-width:560px;line-height:1.7}
.hero-pills{display:flex;flex-wrap:wrap;gap:8px;justify-content:center;margin-top:8px}
.pill{padding:4px 12px;border-radius:999px;background:var(--bg3);border:1px solid var(--brd);
  font-size:.78rem;color:var(--tx2);font-family:var(--mono)}
.hero-btns{display:flex;gap:12px;flex-wrap:wrap;justify-content:center}
.btn-primary{padding:13px 28px;border-radius:var(--r);background:var(--cy);
  color:var(--bg);font-weight:700;font-family:var(--mono);font-size:.88rem;cursor:pointer;
  border:none;transition:all .2s;letter-spacing:.5px}
.btn-primary:hover{background:#33e5ff;transform:translateY(-1px);box-shadow:0 8px 24px rgba(0,217,255,.3)}
.btn-outline{padding:13px 28px;border-radius:var(--r);background:transparent;
  color:var(--cy);font-weight:600;font-family:var(--mono);font-size:.88rem;cursor:pointer;
  border:1.5px solid var(--cy);transition:all .2s}
.btn-outline:hover{background:var(--cy2)}
.hero-stats{display:flex;gap:40px;margin-top:12px;flex-wrap:wrap;justify-content:center}
.stat{text-align:center}
.stat-num{font-family:var(--mono);font-size:1.9rem;font-weight:700;color:var(--cy)}
.stat-lbl{font-size:.78rem;color:var(--tx3);font-family:var(--mono)}

/* CARDS GRID */
.grid-2{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:20px}
.grid-3{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:16px}
.card{background:var(--bg2);border:1px solid var(--brd);border-radius:var(--r2);
  padding:24px;transition:all .22s}
.card:hover{border-color:var(--cy3);transform:translateY(-2px);
  box-shadow:0 8px 32px rgba(0,217,255,.1)}
.card-icon{width:44px;height:44px;border-radius:10px;background:var(--cy2);
  display:flex;align-items:center;justify-content:center;margin-bottom:16px}
.card h3{font-size:1rem;margin-bottom:8px;color:var(--tx)}
.card p{font-size:.87rem;color:var(--tx2);line-height:1.65}

/* TABS */
.tabs-header{display:flex;gap:4px;flex-wrap:wrap;margin-bottom:24px;
  border-bottom:1px solid var(--brd);padding-bottom:12px}
.tab-btn{padding:8px 18px;border-radius:var(--r);background:transparent;border:none;
  color:var(--tx2);font-family:var(--mono);font-size:.82rem;cursor:pointer;transition:all .18s}
.tab-btn:hover{color:var(--tx);background:var(--bg3)}
.tab-btn.active{background:var(--cy2);color:var(--cy);border:1px solid var(--brd)}
.tab-pane{display:none}
.tab-pane.active{display:block}
.module-list{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:12px}
.module-card{background:var(--bg3);border:1px solid var(--brd);border-radius:var(--r);
  padding:16px 18px}
.module-card h4{font-family:var(--mono);font-size:.88rem;color:var(--cy);margin-bottom:6px}
.module-card p{font-size:.82rem;color:var(--tx2);line-height:1.6}

/* MODES */
.modes-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:14px}
.mode-card{background:var(--bg2);border:1.5px solid var(--brd);border-radius:var(--r2);
  padding:22px;transition:all .22s;cursor:default}
.mode-card.featured{border-color:var(--cy);background:linear-gradient(145deg,var(--bg2),rgba(0,217,255,.05))}
.mode-name{font-family:var(--mono);font-weight:700;font-size:.95rem;color:var(--tx);margin-bottom:6px}
.mode-flag{font-family:var(--mono);font-size:.75rem;color:var(--cy);opacity:.7;margin-bottom:10px}
.mode-desc{font-size:.83rem;color:var(--tx2);line-height:1.6;margin-bottom:12px}
.mode-time{display:inline-flex;align-items:center;gap:5px;font-size:.75rem;font-family:var(--mono);
  color:var(--tx3)}

/* SCORE */
.score-bar-wrap{margin:32px 0}
.score-labels{display:flex;justify-content:space-between;font-family:var(--mono);
  font-size:.72rem;margin-bottom:8px;color:var(--tx2)}
.score-bar{height:22px;border-radius:999px;background:linear-gradient(90deg,
  #00FF88 0%,#7AFF00 16%,#FFD600 33%,#FF8C00 55%,#FF4D4D 78%,#CC0000 100%);
  box-shadow:0 0 20px rgba(0,217,255,.1)}
.score-levels{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin-top:28px}
.level-row{display:flex;align-items:center;gap:12px;padding:14px 18px;
  background:var(--bg2);border-radius:var(--r);border:1px solid var(--brd)}
.level-dot{width:12px;height:12px;border-radius:50%;flex-shrink:0}
.level-info h4{font-family:var(--mono);font-size:.85rem}
.level-info p{font-size:.78rem;color:var(--tx2);line-height:1.5}

/* STEPS */
.steps{display:flex;flex-direction:column;gap:16px}
.step{display:flex;gap:18px;align-items:flex-start;background:var(--bg2);
  border:1px solid var(--brd);border-radius:var(--r2);padding:20px 24px}
.step-num{width:36px;height:36px;border-radius:50%;background:var(--cy2);
  border:1.5px solid var(--cy);display:flex;align-items:center;justify-content:center;
  font-family:var(--mono);font-weight:700;color:var(--cy);font-size:.9rem;flex-shrink:0}
.step-body h4{font-family:var(--mono);font-size:.92rem;margin-bottom:5px;color:var(--tx)}
.step-body p{font-size:.85rem;color:var(--tx2);line-height:1.65}

/* TABLE */
.data-table{width:100%;border-collapse:collapse;margin-top:8px}
.data-table th{text-align:left;padding:10px 14px;font-family:var(--mono);font-size:.78rem;
  color:var(--cy);border-bottom:1px solid var(--brd);background:var(--bg2)}
.data-table td{padding:11px 14px;font-size:.84rem;border-bottom:1px solid rgba(255,255,255,.04)}
.data-table td:first-child{font-family:var(--mono);color:var(--cy);font-size:.8rem}
.data-table tr:hover td{background:var(--bg3)}

/* RISK TABLE */
.risk-table{display:flex;flex-direction:column;gap:10px;margin-top:16px}
.risk-row{display:flex;align-items:flex-start;gap:14px;padding:16px 20px;
  border-radius:var(--r);border-left:3px solid transparent}
.risk-row.clean{border-color:var(--grn);background:rgba(0,255,136,.07)}
.risk-row.low{border-color:#7AFF00;background:rgba(122,255,0,.07)}
.risk-row.mod{border-color:var(--yel);background:rgba(255,214,0,.07)}
.risk-row.high{border-color:var(--org);background:rgba(255,140,0,.07)}
.risk-row.crit{border-color:var(--red);background:rgba(255,77,77,.07)}
.risk-badge{min-width:90px;font-family:var(--mono);font-size:.78rem;font-weight:700;padding:4px 10px;
  border-radius:5px;text-align:center}
.risk-score{font-family:var(--mono);font-size:.8rem;color:var(--tx3);min-width:70px}
.risk-desc h4{font-family:var(--mono);font-size:.88rem;margin-bottom:4px}
.risk-desc p{font-size:.82rem;color:var(--tx2);line-height:1.6}

/* REQS */
.req-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:14px}
.req-card{background:var(--bg2);border:1px solid var(--brd);border-radius:var(--r);padding:18px 20px}
.req-card h4{font-family:var(--mono);font-size:.85rem;color:var(--cy);margin-bottom:10px}
.req-card ul{list-style:none;font-size:.83rem;color:var(--tx2);line-height:2}
.req-card li::before{content:'▸ ';color:var(--cy);opacity:.6}

/* FOOTER */
footer{background:var(--bg2);border-top:1px solid var(--brd);padding:40px 24px;text-align:center}
.footer-brand{font-family:var(--mono);font-size:1rem;font-weight:700;color:var(--cy);margin-bottom:8px}
.footer-meta{font-size:.8rem;color:var(--tx3);font-family:var(--mono);line-height:2}
.footer-note{margin-top:16px;padding:14px 20px;background:rgba(255,77,77,.08);
  border:1px solid rgba(255,77,77,.2);border-radius:var(--r);
  font-size:.8rem;color:var(--tx2);max-width:560px;margin-left:auto;margin-right:auto}

/* PRINT */
@media print{
  nav,.hero-btns,.nav-print{display:none!important}
  body{background:#fff;color:#111}
  :root{--bg:#fff;--bg2:#f4f4f4;--bg3:#e8e8e8;--tx:#111;--tx2:#333;--brd:#ccc;--cy:#0077aa}
  section{padding:32px 0;page-break-inside:avoid}
  .card,.module-card,.step,.risk-row,.mode-card{page-break-inside:avoid;margin-bottom:8px}
  h1,h2,h3,h4{color:#0077aa}
  .hero-title{-webkit-text-fill-color:#0077aa;background:none;color:#0077aa}
}
</style>
</head>
<body>

<!-- NAV -->
<nav>
  <div class="nav-brand">
    <svg width="28" height="28" viewBox="0 0 28 28" fill="none">
      <path d="M14 2L3 7v8c0 6.2 4.7 11.2 11 12.5C20.3 26.2 25 21.2 25 15V7L14 2z"
        fill="none" stroke="#00D9FF" stroke-width="1.8"/>
      <path d="M10 14l3 3 5-5" stroke="#00D9FF" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>
    </svg>
    ECHO NERFADOS XDR
  </div>
  <div class="nav-links">
    <a href="#features">Recursos</a>
    <a href="#modules">Módulos</a>
    <a href="#modes">Perfis</a>
    <a href="#score">Score</a>
    <a href="#usage">Uso</a>
    <a href="#requirements">Requisitos</a>
  </div>
  <button class="nav-print" onclick="window.print()">Imprimir / PDF</button>
</nav>

<!-- HERO -->
<section id="hero" style="max-width:1120px">
  <div class="hero-wrap">
    <div class="hero-badge">
      <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
        <path d="M7 1L1.5 3.5v4c0 3.1 2.4 5.6 5.5 6.3 3.1-.7 5.5-3.2 5.5-6.3v-4L7 1z"
          fill="none" stroke="#00D9FF" stroke-width="1.4"/>
      </svg>
      Scanner Forense Anti-Cheat — FiveM
    </div>
    <h1 class="hero-title">Echo Nerfados Shield XDR</h1>
    <p class="hero-sub">Investigação forense digital de máquinas Windows com suspeita de uso de cheats em servidores FiveM. Coleta, correlaciona e pontua evidências de múltiplas fontes sem alterar o sistema investigado.</p>
    <div class="hero-pills">
      <span class="pill">Windows 10/11</span>
      <span class="pill">Self-Contained</span>
      <span class="pill">C# .NET 8</span>
      <span class="pill">CLI + GUI</span>
      <span class="pill">Relatório HTML + JSON</span>
    </div>
    <div class="hero-stats">
      <div class="stat"><div class="stat-num">20+</div><div class="stat-lbl">Módulos</div></div>
      <div class="stat"><div class="stat-num">5</div><div class="stat-lbl">Perfis de Scan</div></div>
      <div class="stat"><div class="stat-num">100+</div><div class="stat-lbl">Regras</div></div>
      <div class="stat"><div class="stat-num">0</div><div class="stat-lbl">Dependências externas</div></div>
    </div>
  </div>
</section>

<!-- FEATURES -->
<section id="features" style="max-width:1120px">
  <div class="section-tag">Recursos Principais</div>
  <h2 class="section-title">Por que Echo Nerfados?</h2>
  <p class="section-sub">Único scanner forense especializado em FiveM com cobertura desde artefatos de execução até memória de processo e detecção anti-forense.</p>
  <div class="grid-2">
    <div class="card">
      <div class="card-icon">
        <svg width="22" height="22" fill="none" stroke="#00D9FF" stroke-width="1.8" viewBox="0 0 24 24">
          <circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/>
        </svg>
      </div>
      <h3>Varredura Forense Profunda</h3>
      <p>Analisa mais de 20 fontes de evidência: Prefetch, BAM/DAM, Amcache, ShimCache, USN Journal, Event Logs, Registro, memória de processo e muito mais.</p>
    </div>
    <div class="card">
      <div class="card-icon">
        <svg width="22" height="22" fill="none" stroke="#00D9FF" stroke-width="1.8" viewBox="0 0 24 24">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
        </svg>
      </div>
      <h3>Detecção de Cheats Conhecidos</h3>
      <p>Base de dados com executáveis, hashes SHA1 e padrões de famílias conhecidas: Eulen, RedENGINE, GOSTH, Susano, Nightfall e dezenas de outros.</p>
    </div>
    <div class="card">
      <div class="card-icon">
        <svg width="22" height="22" fill="none" stroke="#00D9FF" stroke-width="1.8" viewBox="0 0 24 24">
          <path d="M3 3h7v7H3z"/><path d="M14 3h7v7h-7z"/><path d="M14 14h7v7h-7z"/><path d="M3 14h7v7H3z"/>
        </svg>
      </div>
      <h3>Anti-Forense Detection</h3>
      <p>Detecta scripts de limpeza (anti-echo.py), deleção de USN Journal, wipe de Event Logs, limpeza de JumpLists, reg delete em chaves forenses e domínios C2 conhecidos.</p>
    </div>
    <div class="card">
      <div class="card-icon">
        <svg width="22" height="22" fill="none" stroke="#00D9FF" stroke-width="1.8" viewBox="0 0 24 24">
          <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>
        </svg>
      </div>
      <h3>Score de Risco Calibrado</h3>
      <p>Sistema de pontuação 0–100 com ponderação por categoria e nível de risco. Rótulo automático: Limpo, Baixo, Moderado, Elevado, Alto, Crítico.</p>
    </div>
    <div class="card">
      <div class="card-icon">
        <svg width="22" height="22" fill="none" stroke="#00D9FF" stroke-width="1.8" viewBox="0 0 24 24">
          <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
          <polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/>
          <line x1="16" y1="17" x2="8" y2="17"/>
        </svg>
      </div>
      <h3>Relatórios Completos</h3>
      <p>HTML interativo, sumário executivo, TXT para envio por mensagem, JSON estruturado por módulo e manifest com hashes para cadeia de custódia.</p>
    </div>
    <div class="card">
      <div class="card-icon">
        <svg width="22" height="22" fill="none" stroke="#00D9FF" stroke-width="1.8" viewBox="0 0 24 24">
          <circle cx="12" cy="12" r="3"/><path d="M19.07 4.93a10 10 0 0 1 0 14.14"/>
          <path d="M4.93 4.93a10 10 0 0 0 0 14.14"/>
        </svg>
      </div>
      <h3>Perfis Flexíveis</h3>
      <p>Cinco perfis: Rápido (triagem), Completo, Profundo, FiveM (investigação completa) e Florence (modo conservador para casos com poucas corroborações).</p>
    </div>
  </div>
</section>

<!-- MÓDULOS -->
<section id="modules" style="max-width:1120px">
  <div class="section-tag">Módulos de Detecção</div>
  <h2 class="section-title">Cobertura Forense Completa</h2>
  <p class="section-sub">Cada módulo opera de forma independente e os resultados são correlacionados automaticamente pelo motor de análise.</p>
  <div class="tabs-header">
    <button class="tab-btn active" data-tab="exec">Execução</button>
    <button class="tab-btn" data-tab="cheats">Cheats</button>
    <button class="tab-btn" data-tab="antifor">Anti-Forense</button>
    <button class="tab-btn" data-tab="tamper">Tampering</button>
    <button class="tab-btn" data-tab="mem">Memória</button>
    <button class="tab-btn" data-tab="net">Rede &amp; Browser</button>
    <button class="tab-btn" data-tab="arts">Artefatos</button>
  </div>

  <div class="tab-pane active" id="tab-exec">
    <div class="module-list">
      <div class="module-card"><h4>BAM/DAM</h4><p>Background Activity Monitor — histórico de processos executados nos últimos 30 dias direto no registro do Windows.</p></div>
      <div class="module-card"><h4>Prefetch</h4><p>Arquivos .pf em C:\Windows\Prefetch — confirma execução mesmo após deleção do executável.</p></div>
      <div class="module-card"><h4>ShimCache</h4><p>AppCompatCache — registro de executáveis carregados pelo sistema, inclui entradas pós-deleção.</p></div>
      <div class="module-card"><h4>Amcache</h4><p>SHA1 de executáveis — detecta arquivos que não existem mais no disco e confirma identidade por hash.</p></div>
      <div class="module-card"><h4>UserAssist</h4><p>Contadores de execução via Explorer gravados em NTUSER.DAT — quantas vezes cada programa foi aberto.</p></div>
      <div class="module-card"><h4>LNK Recent</h4><p>Atalhos .lnk de arquivos abertos recentemente — revelam caminhos de acesso mesmo que os arquivos tenham sido deletados.</p></div>
      <div class="module-card"><h4>Jump Lists</h4><p>Histórico de arquivos abertos por aplicação. Revela caminhos de cheats mesmo após limpeza manual da pasta.</p></div>
      <div class="module-card"><h4>Timeline</h4><p>Linha do tempo unificada cruzando Prefetch, BAM, LNK, Downloads e Temp para correlação temporal precisa.</p></div>
    </div>
  </div>

  <div class="tab-pane" id="tab-cheats">
    <div class="module-list">
      <div class="module-card"><h4>Known Cheats</h4><p>Busca por nome exato e hash SHA1 de executáveis de cheats conhecidos: Eulen, RedENGINE, GOSTH, farinhafree, Susano, Nightfall e dezenas de outros.</p></div>
      <div class="module-card"><h4>File System</h4><p>Varre Desktop, Downloads, AppData e Temp por executáveis suspeitos — nomes, keywords e padrões característicos de loaders.</p></div>
      <div class="module-card"><h4>RedENGINE Artifacts</h4><p>Configurações específicas do executor redENGINE (settings.cock, menus .lua, imgui.ini, WinRAR associado) — presença indica uso do executor FiveM.</p></div>
      <div class="module-card"><h4>External Tool Residue</h4><p>Rastros de Process Hacker, CheatEngine, x64dbg, Everything, Wireshark no Prefetch — ferramentas de análise/bypass frequentemente presentes em máquinas com cheat.</p></div>
    </div>
  </div>

  <div class="tab-pane" id="tab-antifor">
    <div class="module-list">
      <div class="module-card"><h4>Anti-Forensic Scripts</h4><p>Detecta scripts .py/.bat/.ps1/.vbs com padrões de limpeza coordenada: wipe de eventos, reg delete em chaves forenses, ClearMyTracks, limpeza de JumpLists/Prefetch.</p></div>
      <div class="module-card"><h4>USN Journal</h4><p>Diário NTFS: cheats criados/deletados; deleção de .evtx (Critical); limpeza em massa de JumpLists (Critical); artefatos DriverBooster loader.</p></div>
      <div class="module-card"><h4>Event Viewer — Anti-Forense</h4><p>Detecta via 4688: wevtutil cl, fsutil usn deletejournal, rundll32 ClearMyTracks, reg delete BAM/UserAssist/AppCompatCache, python anti-echo, wscript getadmin.vbs.</p></div>
      <div class="module-card"><h4>Domínios C2 Conhecidos</h4><p>Scripts referenciando api.tzproject.com, lmarket.fr ou ovix.one — infraestrutura de bypass FiveM conhecida — Critical em scripts executáveis.</p></div>
    </div>
  </div>

  <div class="tab-pane" id="tab-tamper">
    <div class="module-list">
      <div class="module-card"><h4>System Tampering</h4><p>Bypass Windows 11 via LabConfig/MoSetup, BatchGotAdmin (getadmin.vbs), VulnerableDriverBlocklistEnable=0 — pré-requisito para cheats via driver vulnerável (BYOVD).</p></div>
      <div class="module-card"><h4>System Reset/Restore</h4><p>Detecta reinstalação, reset ou restauração do Windows — esses eventos destroem evidências e exigem nota no laudo.</p></div>
      <div class="module-card"><h4>Registry Persistence</h4><p>IFEO, AppInit DLLs, Winlogon, BootExecute — mecanismos de persistência e injeção via registro.</p></div>
      <div class="module-card"><h4>Driver &amp; Kernel</h4><p>Drivers não assinados, caminhos suspeitos, drivers instalados recentemente — base para cheats kernel-mode.</p></div>
      <div class="module-card"><h4>Services</h4><p>Serviços instalados com nomes suspeitos — loaders e cheats frequentemente instalam serviços para persistência.</p></div>
      <div class="module-card"><h4>Event Viewer — Sistema</h4><p>Log Security/System limpos (1102/104), horário alterado (4616), serviços instalados (7045), cobertura insuficiente de log (apagamento histórico).</p></div>
    </div>
  </div>

  <div class="tab-pane" id="tab-mem">
    <div class="module-list">
      <div class="module-card"><h4>Process Memory</h4><p>Strings suspeitas em memória de processos em execução — detecta cheats carregados sem arquivo em disco (fileless).</p></div>
      <div class="module-card"><h4>Memory DLL Trace</h4><p>DLLs carregadas, módulos ocultos, manual map e regiões executáveis sem backing em processos FiveM/GTA — técnica principal de cheats avançados.</p></div>
      <div class="module-card"><h4>Memory String Scan</h4><p>Strings de famílias de cheat conhecidas em memória de FiveM/GTA V — confirma presença ativa em sessão de jogo.</p></div>
    </div>
    <p style="margin-top:16px;font-size:.82rem;color:var(--tx3);font-family:var(--mono)">
      ▸ Requer conta Administrador + perfil Deep ou FiveM
    </p>
  </div>

  <div class="tab-pane" id="tab-net">
    <div class="module-list">
      <div class="module-card"><h4>Browser Downloads</h4><p>Downloads do Chrome, Edge, Brave, Opera e Firefox — executáveis e URLs suspeitos. Evidência forte quando o domínio de download é cheat-shop.</p></div>
      <div class="module-card"><h4>SRUM</h4><p>System Resource Usage Monitor (SRUDB.dat) — uso de rede por processo nos últimos 30–60 dias. Confirma atividade de rede de executáveis suspeitos.</p></div>
      <div class="module-card"><h4>Network</h4><p>Histórico de redes Wi-Fi conectadas — correlação de localização com datas de uso do jogo.</p></div>
    </div>
  </div>

  <div class="tab-pane" id="tab-arts">
    <div class="module-list">
      <div class="module-card"><h4>ShellBags</h4><p>Histórico de navegação de pastas — revela acesso a diretórios suspeitos mesmo após deleção da pasta e dos arquivos.</p></div>
      <div class="module-card"><h4>Recycle Bin</h4><p>Caminho original e data de deleção de arquivos na Lixeira — confirma localização real de executáveis enviados para lixeira.</p></div>
      <div class="module-card"><h4>NVIDIA Artifacts</h4><p>Timestamps de sessão GPU — confirma execução de aplicativo gráfico (jogo) em sessões específicas. Corrobora evidências temporais.</p></div>
      <div class="module-card"><h4>Registry Artifacts</h4><p>Autoruns, Run keys, MUICache, OpenWith — rastros de execução e configuração de programas.</p></div>
    </div>
  </div>
</section>

<!-- MODOS -->
<section id="modes" style="max-width:1120px">
  <div class="section-tag">Perfis de Varredura</div>
  <h2 class="section-title">Escolha o Nível Certo</h2>
  <p class="section-sub">Cada perfil é otimizado para um cenário de investigação específico, balanceando velocidade e profundidade.</p>
  <div class="modes-grid">
    <div class="mode-card">
      <div class="mode-name">Rápido</div>
      <div class="mode-flag">--profile fast</div>
      <p class="mode-desc">Módulos core sem USN Journal, memória ou drivers. Ideal para triagem inicial de múltiplas máquinas.</p>
      <span class="mode-time">⏱ 1–2 min</span>
    </div>
    <div class="mode-card">
      <div class="mode-name">Completo</div>
      <div class="mode-flag">--profile full (padrão)</div>
      <p class="mode-desc">Todos os módulos sem memória de processo. Balanceado para investigação padrão.</p>
      <span class="mode-time">⏱ 3–5 min</span>
    </div>
    <div class="mode-card featured">
      <div class="mode-name">FiveM</div>
      <div class="mode-flag">--profile fivem ★ Recomendado</div>
      <p class="mode-desc">Otimizado para investigação FiveM: todos os módulos forenses + memória de processo + módulos de jogo. Máxima cobertura.</p>
      <span class="mode-time">⏱ 5–8 min</span>
    </div>
    <div class="mode-card">
      <div class="mode-name">Profundo</div>
      <div class="mode-flag">--profile deep</div>
      <p class="mode-desc">Igual ao FiveM com análise de memória completa de todos os processos, não apenas FiveM/GTA.</p>
      <span class="mode-time">⏱ 6–10 min</span>
    </div>
    <div class="mode-card">
      <div class="mode-name">Florence</div>
      <div class="mode-flag">--profile florence</div>
      <p class="mode-desc">Modo conservador: exige ≥2 módulos confirmando a mesma entidade antes de elevar o risco. Reduz falsos positivos em casos ambíguos.</p>
      <span class="mode-time">⏱ 5–8 min</span>
    </div>
  </div>
</section>

<!-- SCORE -->
<section id="score" style="max-width:1120px">
  <div class="section-tag">Sistema de Score</div>
  <h2 class="section-title">Risco Quantificado</h2>
  <p class="section-sub">Cada finding é ponderado por categoria e nível. O score final (0–100) agrega todas as evidências com cap por categoria para evitar inflação de um único módulo.</p>
  <div class="score-bar-wrap">
    <div class="score-labels">
      <span>0 — Limpo</span>
      <span>15 — Baixo</span>
      <span>35 — Moderado</span>
      <span>60 — Elevado</span>
      <span>80 — Alto</span>
      <span>100 — Crítico</span>
    </div>
    <div class="score-bar"></div>
  </div>
  <div class="score-levels">
    <div class="level-row"><div class="level-dot" style="background:#00FF88"></div>
      <div class="level-info"><h4>Critical</h4><p>Evidência direta e forte de cheat ou anti-forense agressivo</p></div></div>
    <div class="level-row"><div class="level-dot" style="background:#FF4D4D"></div>
      <div class="level-info"><h4>High</h4><p>Indicador forte — exige correlação para conclusão definitiva</p></div></div>
    <div class="level-row"><div class="level-dot" style="background:#FF8C00"></div>
      <div class="level-info"><h4>Medium</h4><p>Indício — sozinho não é suficiente para conclusão</p></div></div>
    <div class="level-row"><div class="level-dot" style="background:#FFD600"></div>
      <div class="level-info"><h4>Low</h4><p>Nota para investigador — complementar</p></div></div>
    <div class="level-row"><div class="level-dot" style="background:#9fa6bc"></div>
      <div class="level-info"><h4>Info</h4><p>Registro informativo — sem impacto no score</p></div></div>
  </div>
</section>

<!-- USO -->
<section id="usage" style="max-width:900px">
  <div class="section-tag">Guia de Uso</div>
  <h2 class="section-title">Uso em Campo</h2>
  <p class="section-sub">Cinco passos para uma investigação completa. O processo inteiro leva menos de 10 minutos.</p>
  <div class="steps">
    <div class="step">
      <div class="step-num">1</div>
      <div class="step-body">
        <h4>Instalar como Administrador</h4>
        <p>Executar <code style="background:var(--bg3);padding:2px 6px;border-radius:4px;font-family:var(--mono);font-size:.82rem">EchoNerfadosSetup-RC-*.exe</code> na máquina investigada com conta Administrador. Sem Administrador, os módulos de Prefetch, USN Journal e memória são ignorados.</p>
      </div>
    </div>
    <div class="step">
      <div class="step-num">2</div>
      <div class="step-body">
        <h4>Abrir a Interface Gráfica</h4>
        <p>Clicar no atalho "Echo Nerfados Shield XDR" criado na área de trabalho. A GUI abre com campo para Suspeito, Investigador e Número do Caso.</p>
      </div>
    </div>
    <div class="step">
      <div class="step-num">3</div>
      <div class="step-body">
        <h4>Selecionar Perfil FiveM e Iniciar</h4>
        <p>Preencher os campos de identificação, selecionar perfil <strong style="color:var(--cy)">FiveM</strong> e clicar em Iniciar Varredura. A barra de progresso mostra o módulo em execução.</p>
      </div>
    </div>
    <div class="step">
      <div class="step-num">4</div>
      <div class="step-body">
        <h4>Aguardar a Conclusão (5–8 min)</h4>
        <p>O scanner coleta evidências de todas as fontes configuradas. Ao concluir, exibe o score final e o rótulo de risco na tela de resultado.</p>
      </div>
    </div>
    <div class="step">
      <div class="step-num">5</div>
      <div class="step-body">
        <h4>Exportar e Enviar o Relatório</h4>
        <p>Clicar em "Abrir Pasta do Relatório". Compactar a pasta completa (todos os .json + .html + manifest) e enviar para análise. <strong style="color:var(--cy)">Não enviar apenas o .html</strong> — os JSON contêm evidências que o HTML não exibe integralmente.</p>
      </div>
    </div>
  </div>
</section>

<!-- SAÍDAS -->
<section id="outputs" style="max-width:1120px">
  <div class="section-tag">Saídas do Scan</div>
  <h2 class="section-title">Artefatos Gerados</h2>
  <p class="section-sub">Todos os arquivos são salvos em <code style="background:var(--bg3);padding:2px 6px;border-radius:4px;font-family:var(--mono);font-size:.82rem">%ProgramData%\EchoNerfados\Reports\&lt;timestamp&gt;\</code></p>
  <table class="data-table">
    <thead><tr><th>Arquivo</th><th>Conteúdo</th></tr></thead>
    <tbody>
      <tr><td>report.html</td><td>Relatório principal interativo — todos os findings, score, cobertura por módulo</td></tr>
      <tr><td>report_executive.html</td><td>Sumário executivo — conclusão, score, Machine ID, destinado ao gestor</td></tr>
      <tr><td>report.txt</td><td>Versão texto completa — para cópia e envio por mensagem/WhatsApp</td></tr>
      <tr><td>evidence.json</td><td>Todos os findings em JSON estruturado para análise programática</td></tr>
      <tr><td>manifest.json</td><td>Metadados de cadeia de custódia — versão, machine ID, hash de cada arquivo</td></tr>
      <tr><td>manifest.sha256</td><td>Hash do manifest para verificação de integridade</td></tr>
      <tr><td>machine_id.txt</td><td>Machine ID + metadados da máquina investigada</td></tr>
      <tr><td>bamdam_30d.json</td><td>Findings do módulo BAM/DAM</td></tr>
      <tr><td>prefetch_30d.json</td><td>Findings do módulo Prefetch</td></tr>
      <tr><td>antiforensicscripts_30d.json</td><td>Findings de scripts anti-forense</td></tr>
      <tr><td><em>(demais módulos)</em></td><td>Um arquivo JSON por módulo — sempre gerado, mesmo quando vazio</td></tr>
    </tbody>
  </table>
</section>

<!-- INTERPRETAÇÃO -->
<section id="interpretation" style="max-width:900px">
  <div class="section-tag">Interpretação</div>
  <h2 class="section-title">Como Agir pelo Score</h2>
  <p class="section-sub">O score é uma síntese — sempre revisar os findings críticos individualmente antes de emitir o laudo.</p>
  <div class="risk-table">
    <div class="risk-row clean">
      <span class="risk-badge" style="background:rgba(0,255,136,.15);color:#00FF88">LIMPO</span>
      <span class="risk-score">0</span>
      <div class="risk-desc"><h4>Sem evidência material</h4><p>Nenhum indicador de cheat encontrado. Máquina provavelmente limpa.</p><p style="margin-top:4px;color:var(--tx3);font-size:.78rem">Ação: nenhuma.</p></div>
    </div>
    <div class="risk-row low">
      <span class="risk-badge" style="background:rgba(122,255,0,.15);color:#7AFF00">BAIXO</span>
      <span class="risk-score">1–15</span>
      <div class="risk-desc"><h4>Indícios fracos</h4><p>Ferramentas de análise presentes ou comportamentos ambíguos. Não caracteriza cheat isoladamente.</p><p style="margin-top:4px;color:var(--tx3);font-size:.78rem">Ação: documentar e monitorar.</p></div>
    </div>
    <div class="risk-row mod">
      <span class="risk-badge" style="background:rgba(255,214,0,.15);color:#FFD600">MODERADO</span>
      <span class="risk-score">16–35</span>
      <div class="risk-desc"><h4>Indicadores presentes</h4><p>Evidências que precisam de correlação manual e contexto do jogador.</p><p style="margin-top:4px;color:var(--tx3);font-size:.78rem">Ação: revisão pelo investigador antes de decisão.</p></div>
    </div>
    <div class="risk-row high">
      <span class="risk-badge" style="background:rgba(255,140,0,.15);color:#FF8C00">ELEVADO</span>
      <span class="risk-score">36–60</span>
      <div class="risk-desc"><h4>Indicadores significativos</h4><p>Múltiplas fontes apontando para a mesma entidade. Exige verificação dos findings High individualmente.</p><p style="margin-top:4px;color:var(--tx3);font-size:.78rem">Ação: revisão detalhada + decisão com laudo.</p></div>
    </div>
    <div class="risk-row crit">
      <span class="risk-badge" style="background:rgba(255,77,77,.15);color:#FF4D4D">CRÍTICO</span>
      <span class="risk-score">61–100</span>
      <div class="risk-desc"><h4>Múltiplas fontes confirmadas</h4><p>Cheat ativo ou anti-forense coordenado. Evidências de múltiplas fontes independentes.</p><p style="margin-top:4px;color:var(--tx3);font-size:.78rem">Ação: banir com laudo — encaminhar pasta de relatório completa.</p></div>
    </div>
  </div>
</section>

<!-- REQUISITOS -->
<section id="requirements" style="max-width:1120px">
  <div class="section-tag">Requisitos Técnicos</div>
  <h2 class="section-title">Especificações de Sistema</h2>
  <p class="section-sub">Requisitos para instalação e execução do Echo Nerfados Shield XDR.</p>
  <div class="req-grid">
    <div class="req-card">
      <h4>Sistema Operacional</h4>
      <ul>
        <li>Windows 10 x64 (build 1903+)</li>
        <li>Windows 11 x64</li>
        <li>Servidor Windows não suportado</li>
      </ul>
    </div>
    <div class="req-card">
      <h4>Privilégios</h4>
      <ul>
        <li>Admin recomendado (cobertura máxima)</li>
        <li>Sem admin: Prefetch, USN, Security Log e memória desabilitados</li>
        <li>Com admin: 100% dos módulos disponíveis</li>
      </ul>
    </div>
    <div class="req-card">
      <h4>Runtime</h4>
      <ul>
        <li>.NET 8 embutido (self-contained)</li>
        <li>Sem instalação de runtime necessária</li>
        <li>Sem dependências externas</li>
        <li>Sem conexão com internet para scan</li>
      </ul>
    </div>
    <div class="req-card">
      <h4>Hardware</h4>
      <ul>
        <li>CPU x64 (qualquer geração)</li>
        <li>RAM: 512 MB livres</li>
        <li>Disco: 200 MB para instalação</li>
        <li>Relatórios: 50–200 MB por scan</li>
      </ul>
    </div>
  </div>
</section>

<footer>
  <div class="footer-brand">ECHO NERFADOS SHIELD XDR</div>
  <div class="footer-meta">
    Versão 1.0.0 — Build Teste Interno (EnforceLicense=false)<br>
    Uso exclusivo da equipe de investigação<br>
    Relatórios salvos em %ProgramData%\\EchoNerfados\\Reports\\
  </div>
  <div class="footer-note">
    Esta build não exige licença por Machine ID. O licenciamento por máquina será ativado na versão comercial. Não distribuir para terceiros sem autorização.
  </div>
</footer>

<script>
(function(){
  // Tabs
  document.querySelectorAll('.tab-btn').forEach(function(btn){
    btn.addEventListener('click',function(){
      var tab=btn.dataset.tab;
      document.querySelectorAll('.tab-btn').forEach(function(b){b.classList.remove('active')});
      document.querySelectorAll('.tab-pane').forEach(function(p){p.classList.remove('active')});
      btn.classList.add('active');
      document.getElementById('tab-'+tab).classList.add('active');
    });
  });
})();
</script>
</body>
</html>`;

// ─────────────────────────────────────────────────────────────────────────────
//  ENCRYPTION  (AES-256-GCM + PBKDF2-SHA256)
// ─────────────────────────────────────────────────────────────────────────────
function encryptContent(plaintext, password) {
  const salt       = crypto.randomBytes(16);
  const key        = crypto.pbkdf2Sync(password, salt, ITERATIONS, 32, 'sha256');
  const iv         = crypto.randomBytes(12);
  const cipher     = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const authTag    = cipher.getAuthTag(); // 16 bytes
  // Layout: salt(16) | iv(12) | ciphertext | authTag(16)
  return Buffer.concat([salt, iv, ciphertext, authTag]).toString('base64');
}

// ─────────────────────────────────────────────────────────────────────────────
//  PASSWORD GATE SHELL
// ─────────────────────────────────────────────────────────────────────────────
function buildGate(payload, iterations) {
  return `<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Echo Nerfados Shield XDR</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#060912;display:flex;align-items:center;justify-content:center;
  min-height:100vh;font-family:-apple-system,'Segoe UI',sans-serif}
.gate{width:100%;max-width:380px;padding:0 20px;animation:fadeIn .6s ease}
@keyframes fadeIn{from{opacity:0;transform:translateY(12px)}to{opacity:1;transform:translateY(0)}}
.logo{display:flex;align-items:center;justify-content:center;gap:12px;margin-bottom:28px}
.logo-text{font-family:'Courier New',monospace;font-weight:700;font-size:1.05rem;
  color:#00D9FF;letter-spacing:.5px}
.gate-title{text-align:center;font-family:'Courier New',monospace;font-size:.78rem;
  color:#6b748c;letter-spacing:3px;text-transform:uppercase;margin-bottom:32px}
.gate-box{background:#0f1528;border:1px solid rgba(0,217,255,.2);border-radius:12px;
  padding:32px;box-shadow:0 20px 60px rgba(0,0,0,.6)}
.field-label{font-family:'Courier New',monospace;font-size:.72rem;color:#9fa6bc;
  letter-spacing:1px;text-transform:uppercase;margin-bottom:8px;display:block}
.pw-input{width:100%;padding:13px 16px;background:#0a0e27;border:1px solid rgba(0,217,255,.25);
  border-radius:8px;color:#E8EAED;font-family:'Courier New',monospace;font-size:.95rem;
  outline:none;transition:border .2s;letter-spacing:2px}
.pw-input:focus{border-color:#00D9FF;box-shadow:0 0 0 3px rgba(0,217,255,.1)}
.pw-input::placeholder{color:#3a4050;letter-spacing:1px}
.btn{width:100%;margin-top:16px;padding:13px;background:#00D9FF;border:none;
  border-radius:8px;color:#060912;font-weight:700;font-family:'Courier New',monospace;
  font-size:.88rem;cursor:pointer;letter-spacing:1px;transition:all .2s}
.btn:hover{background:#33e5ff;transform:translateY(-1px);box-shadow:0 6px 20px rgba(0,217,255,.3)}
.btn:disabled{opacity:.5;cursor:wait;transform:none;box-shadow:none}
.error{display:none;margin-top:14px;padding:10px 14px;background:rgba(255,77,77,.1);
  border:1px solid rgba(255,77,77,.3);border-radius:6px;font-family:'Courier New',monospace;
  font-size:.78rem;color:#FF4D4D;text-align:center}
.loading{display:none;margin-top:14px;text-align:center;font-family:'Courier New',monospace;
  font-size:.75rem;color:#6b748c;letter-spacing:1px}
.dots::after{content:'...';animation:dots 1.4s steps(4,end) infinite}
@keyframes dots{0%,20%{content:'.'}40%{content:'..'}60%{content:'...'}80%,100%{content:''}}
</style>
</head>
<body>
<div class="gate">
  <div class="logo">
    <svg width="36" height="36" viewBox="0 0 36 36" fill="none">
      <path d="M18 3L4 9v10c0 8.4 6 14.8 14 16.4C26 33.8 32 27.4 32 19V9L18 3z"
        fill="none" stroke="#00D9FF" stroke-width="2"/>
      <path d="M13 18l4 4 6-7" stroke="#00D9FF" stroke-width="2"
        stroke-linecap="round" stroke-linejoin="round"/>
    </svg>
    <span class="logo-text">ECHO NERFADOS XDR</span>
  </div>
  <p class="gate-title">Acesso Restrito</p>
  <div class="gate-box">
    <form id="f" autocomplete="off">
      <label class="field-label" for="pw">Senha de Acesso</label>
      <input id="pw" class="pw-input" type="password" placeholder="••••••••" autocomplete="off" autofocus>
      <button class="btn" type="submit" id="btn">ACESSAR</button>
      <div class="error" id="err">Senha incorreta. Tente novamente.</div>
      <div class="loading" id="ld">Decriptografando <span class="dots"></span></div>
    </form>
  </div>
</div>

<script>
(function(){
  var PAYLOAD="${payload}";
  var ITER=${iterations};

  function b64ToBytes(b64){
    var bin=atob(b64),buf=new Uint8Array(bin.length);
    for(var i=0;i<bin.length;i++)buf[i]=bin.charCodeAt(i);
    return buf;
  }

  async function decrypt(password){
    var raw=b64ToBytes(PAYLOAD);
    var salt=raw.slice(0,16);
    var iv=raw.slice(16,28);
    // ciphertext + authTag (last 16 bytes) — Web Crypto GCM expects them together
    var data=raw.slice(28);

    var enc=new TextEncoder();
    var keyMat=await crypto.subtle.importKey('raw',enc.encode(password),
      {name:'PBKDF2'},false,['deriveKey']);
    var key=await crypto.subtle.deriveKey(
      {name:'PBKDF2',salt:salt,iterations:ITER,hash:'SHA-256'},
      keyMat,{name:'AES-GCM',length:256},false,['decrypt']);
    var plain=await crypto.subtle.decrypt({name:'AES-GCM',iv:iv},key,data);
    return new TextDecoder().decode(plain);
  }

  document.getElementById('f').onsubmit=async function(e){
    e.preventDefault();
    var pw=document.getElementById('pw').value;
    if(!pw)return;
    var btn=document.getElementById('btn');
    var err=document.getElementById('err');
    var ld=document.getElementById('ld');
    btn.disabled=true;err.style.display='none';ld.style.display='block';
    try{
      var html=await decrypt(pw);
      document.open('text/html','replace');
      document.write(html);
      document.close();
    }catch(ex){
      err.style.display='block';
      btn.disabled=false;ld.style.display='none';
      document.getElementById('pw').value='';
      document.getElementById('pw').focus();
    }
  };
})();
</script>
</body>
</html>`;
}

// ─────────────────────────────────────────────────────────────────────────────
//  BUILD
// ─────────────────────────────────────────────────────────────────────────────
console.log('[build] Encriptando apresentação com AES-256-GCM + PBKDF2...');

const encryptedPayload = encryptContent(PRESENTATION, PASSWORD);
const indexHtml        = buildGate(encryptedPayload, ITERATIONS);

const outIndex = path.join(OUT_DIR, 'index.html');
fs.writeFileSync(outIndex, indexHtml, 'utf8');

const payloadKB = Math.round(Buffer.byteLength(encryptedPayload, 'utf8') / 1024);
const totalKB   = Math.round(Buffer.byteLength(indexHtml, 'utf8') / 1024);

console.log('[build] OK');
console.log('  Saída   :', outIndex);
console.log('  Payload :', payloadKB + ' KB (encriptado)');
console.log('  Total   :', totalKB + ' KB');
console.log('  Senha   :', PASSWORD);
console.log('  Algoritmo: AES-256-GCM + PBKDF2-SHA256 (' + ITERATIONS.toLocaleString() + ' iterações)');
console.log('[build] Para PDF: abrir index.html no Chrome e usar Ctrl+P → Salvar como PDF');
