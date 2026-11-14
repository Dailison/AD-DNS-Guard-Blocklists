# 2D Threat Intelligence - listas de IPs maliciosos

Listas públicas de endereços IP que tentaram se conectar em **portas-isca** (portas sem uso, como Telnet, RDP, MySQL, Redis, VNC) de
roteadores MikroTik da 2D Tecnologia expostos na Internet. Nenhum serviço real escuta nessas portas, então quem bate nelas está
varrendo a rede em busca de alvos. Publicamos a cada hora os IPs com bloqueio ativo; cada IP sai da lista quando o bloqueio expira.

Só o endereço IP é publicado: nenhuma informação de roteador, cliente ou rede interna.

## Listas

| Nível | Arquivo | Endereço (raw) |
|---|---|---|
| 1 | `2dti-nivel-1-observados.txt` | https://raw.githubusercontent.com/Dailison/AD-DNS-Guard-Blocklists/main/threat-intel/2dti-nivel-1-observados.txt |
| 2 | `2dti-nivel-2-confirmados.txt` | https://raw.githubusercontent.com/Dailison/AD-DNS-Guard-Blocklists/main/threat-intel/2dti-nivel-2-confirmados.txt |
| 3 | `2dti-nivel-3-persistentes.txt` | https://raw.githubusercontent.com/Dailison/AD-DNS-Guard-Blocklists/main/threat-intel/2dti-nivel-3-persistentes.txt |

- **Nível 1 - observados:** todos os IPs ativos. Quem foi visto uma só vez fica 24 h.
- **Nível 2 - confirmados:** vistos em 2 ou mais roteadores, ou reincidentes (7 dias). Inclui o nível 3.
- **Nível 3 - persistentes:** reincidência repetida (30 dias). É a lista mais curta e mais confiável.

As listas são **cumulativas**: tudo que está no nível 3 também está no 2, e tudo do 2 está no 1. Escolha o nível conforme a tolerância a
falsos positivos: o nível 1 é o mais amplo; o 3 é o mais seguro para bloquear em qualquer lugar.

## Formato

Texto simples. Linhas iniciadas por `#` são comentários (cabeçalho com data e quantidade de IPs); as demais têm um IP por linha,
IPv4 primeiro e depois IPv6, em ordem numérica.

## MikroTik (RouterOS 7)

Exemplo que baixa a lista de nível 3 e a carrega num address-list IPv4 (rode num scheduler, por exemplo a cada hora). O `timeout`
faz as entradas sumirem sozinhas se o roteador deixar de atualizar. Listas grandes (nível 1) podem passar do limite de tamanho do
`/file get contents`; nesse caso use o nível 2 ou 3, ou um script que processe o arquivo em partes.

```routeros
/tool fetch url="https://raw.githubusercontent.com/Dailison/AD-DNS-Guard-Blocklists/main/threat-intel/2dti-nivel-3-persistentes.txt" dst-path="2dti-n3.txt" check-certificate=yes
:local content [/file get "2dti-n3.txt" contents]
/ip firewall address-list remove [find where list="2DTI-PUBLIC" comment="2DTI-PUBLIC"]
:local pos 0
:while ($pos < [:len $content]) do={
  :local eol [:find $content "\n" $pos]
  :if ([:typeof $eol] = "nil") do={ :set eol [:len $content] }
  :local line [:pick $content $pos $eol]
  :set pos ($eol + 1)
  :if ([:len $line] > 0 && [:pick $line 0 1] != "#" && [:find $line ":"] = nil) do={
    :do { /ip firewall address-list add list="2DTI-PUBLIC" address=$line timeout=2d comment="2DTI-PUBLIC" } on-error={}
  }
}
/file remove "2dti-n3.txt"
# descarte: /ip firewall raw add chain=prerouting src-address-list=2DTI-PUBLIC action=drop
```

## pfSense / OPNsense

Firewall > Aliases > **URL Table (IPs)** com o endereço raw da lista e atualização periódica. Use o alias numa regra de bloqueio na WAN.

## Linux (ipset)

```sh
ipset create 2dti hash:ip -exist
curl -fsS https://raw.githubusercontent.com/Dailison/AD-DNS-Guard-Blocklists/main/threat-intel/2dti-nivel-3-persistentes.txt | grep -v '^#' | grep -v ':' | sed 's/^/add 2dti /' | ipset restore -exist
```

## Falso positivo

Se um IP legítimo foi listado, abra uma [issue](https://github.com/Dailison/AD-DNS-Guard-Blocklists/issues) com o endereço e o motivo. Redes compartilhadas ou dinâmicas podem
aparecer no nível 1; os níveis 2 e 3 exigem mais evidência.

Mantido pela 2D Tecnologia. Sem garantias: use por sua conta e risco.
