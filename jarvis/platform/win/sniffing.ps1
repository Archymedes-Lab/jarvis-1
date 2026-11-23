
$o = @{ drivers = @(); tools = @(); promisc = @() }
foreach ($n in 'npcap','npf','pktmon') {
  $s = Get-Service -Name $n -ErrorAction SilentlyContinue
  if ($s) { $o.drivers += @{ name = $s.Name; status = "$($s.Status)" } }
}
$names = 'Wireshark','dumpcap','tshark','windump','WinDump','rawshark',
         'NetworkMiner','Fiddler','mitmproxy','mitmdump','Netmon','tcpview'
$o.tools = Get-Process -ErrorAction SilentlyContinue |
  Where-Object { $names -contains $_.ProcessName } |
  ForEach-Object { @{ name = $_.ProcessName; id = $_.Id } }
try {
  $o.promisc = Get-CimInstance -Namespace root/StandardCimv2 MSFT_NetAdapter `
    -ErrorAction Stop | Where-Object { $_.PromiscuousMode } |
    ForEach-Object { $_.Name }
} catch { }
[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((ConvertTo-Json $o -Depth 5)))
