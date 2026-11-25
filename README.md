# Netfive Category Feed

Feed de categorias de sites consumido pelo app **Netfive Web Filtering** (Falcon Foundry).

- `dist/feed.json`: feed completo (schema `netfive.category-feed/v1`), lido pelo app.
- `dist/manifest.json`: versão + sha256. O app compara a versão para saber se precisa sincronizar.
- `dist/categories.csv`: mesmo conteúdo no formato de importação do app v1.1 (`category,url`).

## Como é montado
1. **Curadoria Netfive** (`config/curated/<Categoria>.txt`): sempre entra, com prioridade máxima.
2. **Wildcards por categoria** (ex.: `*.bet.br` em Apostas).
3. **Listas abertas** (UT1 Toulouse e Hagezi), filtradas pelo **Tranco Top 1M**, ordenadas por popularidade e cortadas em `max_domains`.
4. `config/never_block.txt`: domínios que nunca entram (SO, M365, Google, Falcon...).

O GitHub Action roda todo dia (e a cada mudança em `config/`) e só publica se o ranking Tranco estiver disponível.

## Atribuição
UT1 Blacklists, Université Toulouse Capitole (CC BY-SA 4.0) · Hagezi DNS Blocklists (GPL-3.0) · Tranco list (tranco-list.eu).
