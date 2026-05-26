<?php
require_once 'config/config.php';
header('Content-Type: application/json');

register_shutdown_function(function() {
    $e = error_get_last();
    if ($e && in_array($e['type'], [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR], true)) {
        if (!headers_sent()) header('HTTP/1.1 500 Internal Server Error');
        echo json_encode(['error' => 'PHP: ' . $e['message'], 'file' => basename($e['file']), 'line' => $e['line']]);
    }
});

$id = intval($_GET['id'] ?? 0);

$subnetRow = $mysqli2->query(
    "SELECT id, group_id, subnet, netmask, cidr, vlan, vlan_name, name, description,
            source_type, addressing_source, collection_source, netdisco_lease_days,
            device_info_source, glpi_inventory_check,
            nmap, dhcp_type, dhcp_topology, dhcp_force_resa,
            dhcp_pool_alert_threshold, dhcp_reservation_only,
            gateway, arpsuck_source, lastseen_default_source, obsolete_days
     FROM subnets WHERE id = $id LIMIT 1"
);
$subnet = $subnetRow ? $subnetRow->fetch_assoc() : null;

// Récupérer les serveurs DHCP associés
if ($subnet) {
    $dhcpServers = [];
    $ds = $mysqli2->query("
        SELECT ds.id, ds.name, ds.ip_address, sds.range_start, sds.range_end
        FROM dhcp_servers ds
        JOIN subnet_dhcp_servers sds ON sds.dhcp_server_id = ds.id
        WHERE sds.subnet_id = $id
        ORDER BY ds.name
    ");
    if ($ds) {
        while ($r = $ds->fetch_assoc()) $dhcpServers[] = $r;
    }

    // Charger les exclusions par serveur
    $exclRes = $mysqli2->query("
        SELECT dhcp_server_id, excl_start, excl_end
        FROM subnet_dhcp_server_exclusions
        WHERE subnet_id = $id
        ORDER BY dhcp_server_id, excl_start
    ");
    $exclusionsBySrv = [];
    if ($exclRes) {
        while ($row = $exclRes->fetch_assoc()) {
            $exclusionsBySrv[(int)$row['dhcp_server_id']][] = [
                'excl_start' => $row['excl_start'],
                'excl_end'   => $row['excl_end'],
            ];
        }
    }
    foreach ($dhcpServers as &$srv) {
        $srv['exclusions'] = $exclusionsBySrv[(int)$srv['id']] ?? [];
    }
    unset($srv);

    $subnet['dhcp_servers'] = $dhcpServers;

    // Statistiques pool DHCP agrégées (somme sur tous les serveurs)
    $psRes = $mysqli2->query("
        SELECT
            SUM(addresses_free)   AS pool_free,
            SUM(addresses_in_use) AS pool_in_use,
            SUM(reserved)         AS pool_reserved,
            MAX(collected_at)     AS last_collected
        FROM dhcp_pool_stats
        WHERE subnet_id = $id
    ");
    if ($psRes && ($ps = $psRes->fetch_assoc()) && $ps['pool_free'] !== null) {
        $pFree  = (int)$ps['pool_free'];
        $pInUse = (int)$ps['pool_in_use'];
        $pResv  = (int)$ps['pool_reserved'];
        $pTotal = $pFree + $pInUse + $pResv;
        $pUsed  = $pInUse + $pResv;
        $subnet['pool_stats'] = [
            'total'          => $pTotal,
            'used'           => $pUsed,
            'free'           => $pFree,
            'in_use'         => $pInUse,
            'reserved'       => $pResv,
            'pct'            => $pTotal > 0 ? (int)round($pUsed / $pTotal * 100) : 0,
            'last_collected' => $ps['last_collected'],
        ];
    } else {
        $subnet['pool_stats'] = null;
    }
}

// IPs avec réservation DHCP dans ce subnet (pour l'éligibilité obsolescence)
$reservedIps = [];
$resRes = $mysqli2->query(
    "SELECT DISTINCT ip_address FROM dhcp_leases
     WHERE subnet_id = $id AND lease_type IN ('reservation_active','reservation_inactive')"
);
if ($resRes) {
    while ($r = $resRes->fetch_assoc()) $reservedIps[$r['ip_address']] = true;
}

$obsoleteDays = isset($subnet['obsolete_days']) && $subnet['obsolete_days'] !== null
    ? (int)$subnet['obsolete_days'] : null;
$thresholdTs  = $obsoleteDays !== null ? strtotime("-{$obsoleteDays} days") : null;

// Inclure l'id dans chaque ligne IP pour le CRUD
$result = $mysqli2->query(
    "SELECT id, ip_address, device_name, device_alias, mac_address,
            host_net_config, dhcp_status, source, network_last_seen,
            seen_on_switch, switch_port, switch_time_first, switch_time_last,
            seen_on_router, router_time_first, router_time_last,
            lastseen_source_override, obsolete_ignore,
            glpi_url, glpi_device_name, glpi_network_alias, glpi_description, glpi_user, glpi_last_sync, glpi_from_cache,
            locked, gateway_override
     FROM ip_addresses WHERE subnet_id = $id"
);

// Indexer les IPs existantes par adresse
$existingByIp = [];
if ($result) {
    while ($row = $result->fetch_assoc()) {
        // Calculer effective_last_seen selon la source configurée
        $row['effective_last_seen'] = computeEffectiveLastSeen(
            $row,
            $row['lastseen_source_override'] ?? $subnet['lastseen_default_source'] ?? null
        );
        $row['obsolete_ignore'] = (int)($row['obsolete_ignore'] ?? 0);
        $row['is_obsolete']     = computeIsObsolete($row, $thresholdTs, $reservedIps);
        $existingByIp[$row['ip_address']] = $row;
    }
}

$ips = [];
$cidrStr  = $subnet['cidr'] ?? null;
$cidrNum  = $cidrStr ? intval(ltrim($cidrStr, '/')) : null;
$netLong  = $subnet ? ip2long($subnet['subnet']) : false;

// Charger les enregistrements DNS pour la plage du subnet
$dnsMap = [];
if ($subnet && $cidrNum !== null && $netLong !== false && $cidrNum >= 16) {
    $firstIpEsc = $mysqli2->real_escape_string(long2ip($netLong + 1));
    $lastIpEsc  = $mysqli2->real_escape_string(long2ip($netLong + (1 << (32 - $cidrNum)) - 2));
    $dnsRes = $mysqli2->query("
        SELECT ip_address, name, type, value, zone, is_dynamic
        FROM dns_records
        WHERE ip_address IS NOT NULL
          AND INET_ATON(ip_address) BETWEEN INET_ATON('$firstIpEsc') AND INET_ATON('$lastIpEsc')
        ORDER BY ip_address, type, name
    ");
} elseif (!empty($existingByIp)) {
    $ipsIn  = implode("','", array_map([$mysqli2, 'real_escape_string'], array_keys($existingByIp)));
    $dnsRes = $mysqli2->query("
        SELECT ip_address, name, type, value, zone, is_dynamic
        FROM dns_records WHERE ip_address IN ('$ipsIn')
        ORDER BY ip_address, type, name
    ");
} else {
    $dnsRes = null;
}
if ($dnsRes) {
    while ($dr = $dnsRes->fetch_assoc()) {
        $dnsMap[$dr['ip_address']][] = [
            'name'       => $dr['name'],
            'type'       => $dr['type'],
            'value'      => $dr['value'],
            'zone'       => $dr['zone'],
            'is_dynamic' => (int)$dr['is_dynamic'],
        ];
    }
}

// Résoudre CNAME et SRV qui ciblent un nom A/AAAA connu dans ce subnet
// Construire la map nom_A -> ip
$nameToIp = [];
foreach ($dnsMap as $ip => $recs) {
    foreach ($recs as $r) {
        if ($r['type'] === 'A' || $r['type'] === 'AAAA') {
            $nameToIp[$r['name']] = $ip;
        }
    }
}
if (!empty($nameToIp)) {
    $namesEsc = implode("','", array_map([$mysqli2, 'real_escape_string'], array_keys($nameToIp)));

    // CNAME : value = nom cible direct
    $cnameRes = $mysqli2->query("
        SELECT name, value, zone, is_dynamic
        FROM dns_records
        WHERE type = 'CNAME' AND value IN ('$namesEsc')
        ORDER BY name
    ");
    if ($cnameRes) {
        while ($cr = $cnameRes->fetch_assoc()) {
            $targetIp = $nameToIp[$cr['value']] ?? null;
            if (!$targetIp) continue;
            $dnsMap[$targetIp][] = [
                'name'       => $cr['name'],
                'type'       => 'CNAME',
                'value'      => $cr['value'],
                'zone'       => $cr['zone'],
                'is_dynamic' => (int)$cr['is_dynamic'],
            ];
        }
    }

    // SRV : value = "priority weight port target" — extraire le target (4e champ)
    $srvRes = $mysqli2->query("
        SELECT name, value, zone, is_dynamic
        FROM dns_records WHERE type = 'SRV'
        ORDER BY name
    ");
    if ($srvRes) {
        while ($sr = $srvRes->fetch_assoc()) {
            $parts  = explode(' ', $sr['value']);
            $target = count($parts) >= 4 ? rtrim($parts[3], '.') : null;
            if (!$target || !isset($nameToIp[$target])) continue;
            $dnsMap[$nameToIp[$target]][] = [
                'name'       => $sr['name'],
                'type'       => 'SRV',
                'value'      => $sr['value'],
                'zone'       => $sr['zone'],
                'is_dynamic' => (int)$sr['is_dynamic'],
            ];
        }
    }
}

if ($cidrNum !== null && $netLong !== false && $cidrNum >= 16) {
    // Générer toute la plage (réseau+1 → broadcast-1), max 8192 IPs
    $firstLong = $netLong + 1;
    $lastLong  = $netLong + (1 << (32 - $cidrNum)) - 2;
    $lastLong  = min($lastLong, $firstLong + 8191);

    $emptyRow = [
        'id' => null, 'ip_address' => null, 'device_name' => null, 'device_alias' => null,
        'mac_address' => null, 'host_net_config' => null, 'dhcp_status' => null,
        'source' => null, 'network_last_seen' => null,
        'seen_on_switch' => null, 'switch_port' => null, 'switch_time_first' => null, 'switch_time_last' => null,
        'seen_on_router' => null, 'router_time_first' => null, 'router_time_last' => null,
        'lastseen_source_override' => null, 'effective_last_seen' => null,
        'obsolete_ignore' => 0, 'is_obsolete' => false,
        'glpi_url' => null, 'glpi_device_name' => null, 'glpi_network_alias' => null,
        'glpi_description' => null, 'glpi_user' => null, 'glpi_last_sync' => null, 'glpi_from_cache' => 0,
        'locked' => 'no', 'gateway_override' => null, 'dns_records' => [],
    ];

    for ($l = $firstLong; $l <= $lastLong; $l++) {
        $ip = long2ip($l);
        if (isset($existingByIp[$ip])) {
            $row = $existingByIp[$ip];
            $row['dns_records'] = $dnsMap[$ip] ?? [];
            $ips[] = $row;
        } else {
            $ips[] = array_merge($emptyRow, ['ip_address' => $ip, 'dns_records' => $dnsMap[$ip] ?? []]);
        }
    }
} else {
    // Subnet trop grand ou CIDR inconnu : uniquement les IPs existantes
    foreach ($existingByIp as $ip => $row) {
        $row['dns_records'] = $dnsMap[$ip] ?? [];
        $ips[] = $row;
    }
    usort($ips, fn($a, $b) => ip2long($a['ip_address']) <=> ip2long($b['ip_address']));
}

echo json_encode(['subnet' => $subnet, 'ips' => $ips]);

/**
 * Détermine si une IP est potentiellement obsolète.
 *
 * @param array    $ip           Ligne ip_addresses (avec effective_last_seen calculé)
 * @param int|null $thresholdTs  Timestamp seuil (null = feature désactivée sur le subnet)
 * @param array    $reservedIps  Map ip_address → true pour les IPs avec réservation DHCP
 */
function computeIsObsolete(array $ip, ?int $thresholdTs, array $reservedIps): bool
{
    if ($thresholdTs === null)  return false;  // feature désactivée
    if ($ip['obsolete_ignore']) return false;  // exemptée manuellement
    if (!$ip['mac_address'])    return false;  // pas de MAC → non traçable

    // Éligible si : IP manuelle/statique OU réservation DHCP
    // Les baux dynamiques purs sont ignorés
    $eligible = ($ip['source'] === 'MANUAL')
             || ($ip['host_net_config'] === 'Static')
             || isset($reservedIps[$ip['ip_address']]);
    if (!$eligible) return false;

    // Jamais vue sur le réseau → réservation fantôme potentielle
    if (!$ip['effective_last_seen']) return true;

    $lastSeenTs = strtotime($ip['effective_last_seen']);
    return $lastSeenTs !== false && $lastSeenTs < $thresholdTs;
}

/**
 * Détermine le "dernier vu" effectif d'une IP selon la source configurée.
 *
 * @param array       $ip     Ligne ip_addresses avec tous les champs de dates
 * @param string|null $source 'dhcp' | 'arp' | 'mac' | null (= max toutes sources)
 * @return string|null Datetime MySQL ou null
 */
function computeEffectiveLastSeen(array $ip, ?string $source): ?string
{
    switch ($source) {
        case 'dhcp':
            return $ip['network_last_seen'] ?? null;
        case 'arp':
            return $ip['router_time_last'] ?? null;
        case 'mac':
            return $ip['switch_time_last'] ?? null;
        default:
            // Aucune source configurée : prendre la date la plus récente
            $candidates = array_filter([
                $ip['network_last_seen']  ?? null,
                $ip['router_time_last']   ?? null,
                $ip['switch_time_last']   ?? null,
            ]);
            if (empty($candidates)) return null;
            rsort($candidates);
            return $candidates[0];
    }
}
