<?php
require_once '../config/config.php';
header('Content-Type: application/json');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    echo json_encode(['error' => 'Méthode non autorisée']);
    exit;
}

$id          = intval($_POST['id'] ?? 0);
$nmap        = $_POST['nmap'] ?? 'no';
$dhcpForceResa = $_POST['dhcp_force_resa'] ?? 'no';
$serverIds   = isset($_POST['dhcp_server_ids']) ? (array)$_POST['dhcp_server_ids'] : [];

// Nouveaux champs source d'adressage / source de collecte
$addrSrc    = $_POST['addressing_source'] ?? '';
if (!in_array($addrSrc, ['dhcp', 'static'], true)) $addrSrc = '';

$collectSrc = $_POST['collection_source'] ?? 'manual';
if (!in_array($collectSrc, ['dhcp_agent', 'netdisco', 'manual'], true)) $collectSrc = 'manual';

$netdiscoLeaseDays = intval($_POST['netdisco_lease_days'] ?? 0);
$netdiscoLeaseVal  = ($collectSrc === 'netdisco' && $netdiscoLeaseDays > 0) ? $netdiscoLeaseDays : 'NULL';

// source_type maintenu en cohérence pour rétrocompatibilité
$sourceType = ($collectSrc === 'dhcp_agent') ? 'DHCP' : 'MANUAL';

if (!in_array($nmap,          ['yes', 'no'], true)) $nmap          = 'no';
if (!in_array($dhcpForceResa, ['yes', 'no'], true)) $dhcpForceResa = 'no';

$stSrc       = $mysqli2->real_escape_string($sourceType);
$stAddrSrc   = $mysqli2->real_escape_string($addrSrc);
$addrSrcVal  = $addrSrc !== '' ? "'$stAddrSrc'" : 'NULL';
$stCollect   = $mysqli2->real_escape_string($collectSrc);
$stNmap      = $mysqli2->real_escape_string($nmap);
$stForceResa = $mysqli2->real_escape_string($dhcpForceResa);
$dhcpType     = $mysqli2->real_escape_string(trim($_POST['dhcp_type']     ?? ''));
$dhcpTypeVal  = $dhcpType !== '' ? "'$dhcpType'" : 'NULL';
$dhcpTopology = $_POST['dhcp_topology'] ?? '';
if (!in_array($dhcpTopology, ['cluster', 'shared'], true)) $dhcpTopology = '';
$dhcpTopologyVal = $dhcpTopology !== '' ? "'$dhcpTopology'" : 'NULL';

$dhcpPoolThreshold = isset($_POST['dhcp_pool_alert_threshold']) && $_POST['dhcp_pool_alert_threshold'] !== ''
    ? max(1, min(100, intval($_POST['dhcp_pool_alert_threshold'])))
    : null;
$dhcpPoolThresholdVal = $dhcpPoolThreshold !== null ? $dhcpPoolThreshold : 'NULL';

$dhcpReservationOnly = $_POST['dhcp_reservation_only'] ?? 'no';
if (!in_array($dhcpReservationOnly, ['yes', 'no'], true)) $dhcpReservationOnly = 'no';
$gateway     = $mysqli2->real_escape_string(trim($_POST['gateway']        ?? ''));
$arpsuckSrc  = $mysqli2->real_escape_string(trim($_POST['arpsuck_source'] ?? ''));
$gatewayVal  = $gateway    !== '' ? "'$gateway'"    : 'NULL';
$arpsuckVal  = $arpsuckSrc !== '' ? "'$arpsuckSrc'" : 'NULL';
$lastseenSrc = $_POST['lastseen_default_source'] ?? '';
if (!in_array($lastseenSrc, ['dhcp', 'arp', 'mac'], true)) $lastseenSrc = '';
$lastseenSrcVal = $lastseenSrc !== '' ? "'$lastseenSrc'" : 'NULL';

$deviceInfoSrc = $_POST['device_info_source'] ?? 'none';
if (!in_array($deviceInfoSrc, ['glpi', 'dhcp', 'none'], true)) $deviceInfoSrc = 'none';
$glpiInvCheck  = $_POST['glpi_inventory_check'] ?? 'no';
if (!in_array($glpiInvCheck, ['yes', 'no'], true)) $glpiInvCheck = 'no';

$obsoleteDaysRaw = $_POST['obsolete_days'] ?? '';
$obsoleteDays    = ($obsoleteDaysRaw !== '' && intval($obsoleteDaysRaw) > 0)
                   ? intval($obsoleteDaysRaw) : null;
$obsoleteDaysVal = $obsoleteDays !== null ? $obsoleteDays : 'NULL';

$stDeviceInfoSrc = $mysqli2->real_escape_string($deviceInfoSrc);
$stGlpiInvCheck  = $mysqli2->real_escape_string($glpiInvCheck);

$name    = $mysqli2->real_escape_string(trim($_POST['name'] ?? ''));
$subnet  = $mysqli2->real_escape_string(trim($_POST['subnet'] ?? ''));
$cidr    = $mysqli2->real_escape_string(trim($_POST['cidr'] ?? ''));
$netmask = $mysqli2->real_escape_string(trim($_POST['netmask'] ?? ''));
$vlan     = $mysqli2->real_escape_string(trim($_POST['vlan'] ?? ''));
$vlanName = $mysqli2->real_escape_string(trim($_POST['vlan_name'] ?? ''));
$desc     = $mysqli2->real_escape_string(trim($_POST['description'] ?? ''));
$groupId = intval($_POST['group_id'] ?? 0);
$gidVal  = $groupId > 0 ? $groupId : 'NULL';

$nameVal    = $name    !== '' ? "'$name'"    : 'NULL';
$subnetVal  = $subnet  !== '' ? "'$subnet'"  : 'NULL';
$cidrVal    = $cidr    !== '' ? "'$cidr'"    : 'NULL';
$netmaskVal = $netmask !== '' ? "'$netmask'" : 'NULL';
$vlanVal     = $vlan     !== '' ? "'$vlan'"     : 'NULL';
$vlanNameVal = $vlanName !== '' ? "'$vlanName'" : 'NULL';
$descVal    = $desc    !== '' ? "'$desc'"    : 'NULL';

// Nouvelles valeurs pour le diff (non-escaped)
$newVals = [
    'name'            => trim($_POST['name']           ?? '') ?: null,
    'subnet'          => trim($_POST['subnet']          ?? '') ?: null,
    'cidr'            => trim($_POST['cidr']            ?? '') ?: null,
    'netmask'         => trim($_POST['netmask']         ?? '') ?: null,
    'vlan'            => trim($_POST['vlan']            ?? '') ?: null,
    'vlan_name'       => trim($_POST['vlan_name']       ?? '') ?: null,
    'description'     => trim($_POST['description']     ?? '') ?: null,
    'source_type'            => $sourceType,
    'addressing_source'      => $addrSrc !== '' ? $addrSrc : null,
    'collection_source'      => $collectSrc,
    'netdisco_lease_days'    => $netdiscoLeaseDays > 0 ? $netdiscoLeaseDays : null,
    'device_info_source'     => $deviceInfoSrc,
    'glpi_inventory_check'   => $glpiInvCheck,
    'nmap'                   => $nmap,
    'dhcp_type'                 => trim($_POST['dhcp_type'] ?? '') ?: null,
    'dhcp_topology'             => $dhcpTopology ?: null,
    'dhcp_pool_alert_threshold' => $dhcpPoolThreshold,
    'dhcp_reservation_only'     => $dhcpReservationOnly,
    'dhcp_force_resa'           => $dhcpForceResa,
    'gateway'         => trim($_POST['gateway']         ?? '') ?: null,
    'arpsuck_source'         => trim($_POST['arpsuck_source']         ?? '') ?: null,
    'lastseen_default_source'=> $lastseenSrc !== '' ? $lastseenSrc : null,
    'obsolete_days'          => $obsoleteDays,
    'group_id'               => $groupId > 0 ? $groupId : null,
];

if ($id > 0) {
    // Fetch old values for diff
    $oldRes = $mysqli2->query(
        "SELECT name, subnet, cidr, netmask, vlan, vlan_name, description,
                source_type, addressing_source, collection_source,
                nmap, dhcp_type, dhcp_force_resa,
                gateway, arpsuck_source, lastseen_default_source, group_id
         FROM subnets WHERE id=$id LIMIT 1"
    );
    $oldVals = $oldRes ? $oldRes->fetch_assoc() : [];

    // UPDATE existing
    $mysqli2->query("UPDATE subnets SET
        name=$nameVal, subnet=$subnetVal, cidr=$cidrVal, netmask=$netmaskVal,
        vlan=$vlanVal, vlan_name=$vlanNameVal, description=$descVal, group_id=$gidVal,
        source_type='$stSrc',
        addressing_source=$addrSrcVal, collection_source='$stCollect',
        netdisco_lease_days=$netdiscoLeaseVal,
        device_info_source='$stDeviceInfoSrc', glpi_inventory_check='$stGlpiInvCheck',
        nmap='$stNmap',
        dhcp_type=$dhcpTypeVal, dhcp_topology=$dhcpTopologyVal,
        dhcp_pool_alert_threshold=$dhcpPoolThresholdVal, dhcp_reservation_only='$dhcpReservationOnly',
        dhcp_force_resa='$stForceResa',
        gateway=$gatewayVal, arpsuck_source=$arpsuckVal,
        lastseen_default_source=$lastseenSrcVal,
        obsolete_days=$obsoleteDaysVal
        WHERE id=$id");
    if ($mysqli2->error) {
        echo json_encode(['error' => $mysqli2->error]);
        exit;
    }

    // Build diff
    $changes = [];
    foreach ($newVals as $f => $nv) {
        $ov = isset($oldVals[$f]) && $oldVals[$f] !== '' ? $oldVals[$f] : null;
        if (($ov ?? '') !== ($nv ?? '')) {
            $changes[$f] = ['old' => $ov, 'new' => $nv];
        }
    }
    $label    = trim($_POST['subnet'] ?? '');
    $sLabel   = $mysqli2->real_escape_string($label);
    $sChanges = $mysqli2->real_escape_string(json_encode($changes, JSON_UNESCAPED_UNICODE));
    $mysqli2->query("INSERT INTO audit_log (entity_type, entity_id, action, label, changes) VALUES ('subnet', $id, 'update', '$sLabel', '$sChanges')");
} else {
    // INSERT new subnet
    if ($subnet === '') {
        echo json_encode(['error' => 'Adresse réseau requise']);
        exit;
    }
    $mysqli2->query("INSERT INTO subnets
        (subnet, cidr, netmask, vlan, vlan_name, name, description,
         source_type, addressing_source, collection_source, netdisco_lease_days,
         device_info_source, glpi_inventory_check, nmap,
         dhcp_type, dhcp_topology, dhcp_pool_alert_threshold, dhcp_reservation_only,
         dhcp_force_resa, gateway, arpsuck_source, lastseen_default_source, obsolete_days, group_id)
        VALUES ($subnetVal, $cidrVal, $netmaskVal, $vlanVal, $vlanNameVal, $nameVal, $descVal,
                '$stSrc', $addrSrcVal, '$stCollect', $netdiscoLeaseVal,
                '$stDeviceInfoSrc', '$stGlpiInvCheck', '$stNmap',
                $dhcpTypeVal, $dhcpTopologyVal, $dhcpPoolThresholdVal, '$dhcpReservationOnly',
                '$stForceResa', $gatewayVal, $arpsuckVal, $lastseenSrcVal, $obsoleteDaysVal, $gidVal)");
    if ($mysqli2->error) {
        echo json_encode(['error' => $mysqli2->error]);
        exit;
    }
    $id = $mysqli2->insert_id;

    $label    = trim($_POST['subnet'] ?? '');
    $sLabel   = $mysqli2->real_escape_string($label);
    $sChanges = $mysqli2->real_escape_string(json_encode(array_filter($newVals, fn($v) => $v !== null), JSON_UNESCAPED_UNICODE));
    $mysqli2->query("INSERT INTO audit_log (entity_type, entity_id, action, label, changes) VALUES ('subnet', $id, 'create', '$sLabel', '$sChanges')");
}

// Resync des serveurs DHCP associés
// dhcp_servers_data : JSON [{id, range_start, range_end, exclusions: [{excl_start, excl_end}]}]
$mysqli2->query("DELETE FROM subnet_dhcp_servers WHERE subnet_id=$id");
$mysqli2->query("DELETE FROM subnet_dhcp_server_exclusions WHERE subnet_id=$id");

$serversData = [];
$rawData = $_POST['dhcp_servers_data'] ?? '';
if ($rawData !== '') {
    $decoded = json_decode($rawData, true);
    if (is_array($decoded)) {
        foreach ($decoded as $entry) {
            $sid = intval($entry['id'] ?? 0);
            if ($sid > 0) {
                $serversData[$sid] = [
                    'range_start' => $mysqli2->real_escape_string(trim($entry['range_start'] ?? '')),
                    'range_end'   => $mysqli2->real_escape_string(trim($entry['range_end']   ?? '')),
                    'exclusions'  => is_array($entry['exclusions'] ?? null) ? $entry['exclusions'] : [],
                ];
            }
        }
    }
}

foreach ($serverIds as $sid) {
    $sid = intval($sid);
    if ($sid <= 0) continue;
    $rs = (isset($serversData[$sid]) && $serversData[$sid]['range_start'] !== '') ? "'" . $serversData[$sid]['range_start'] . "'" : 'NULL';
    $re = (isset($serversData[$sid]) && $serversData[$sid]['range_end']   !== '') ? "'" . $serversData[$sid]['range_end']   . "'" : 'NULL';
    $mysqli2->query("INSERT IGNORE INTO subnet_dhcp_servers (subnet_id, dhcp_server_id, range_start, range_end) VALUES ($id, $sid, $rs, $re)");
    if (isset($serversData[$sid])) {
        foreach ($serversData[$sid]['exclusions'] as $excl) {
            $es = $mysqli2->real_escape_string(trim($excl['excl_start'] ?? ''));
            $ee = $mysqli2->real_escape_string(trim($excl['excl_end']   ?? ''));
            if ($es !== '' && $ee !== '') {
                $mysqli2->query("INSERT INTO subnet_dhcp_server_exclusions (subnet_id, dhcp_server_id, excl_start, excl_end) VALUES ($id, $sid, '$es', '$ee')");
            }
        }
    }
}

// Auto-calculer la topologie si elle n'est pas explicitement définie
if ($dhcpTopology === '') {
    $cntRes = $mysqli2->query("SELECT COUNT(*) AS c FROM subnet_dhcp_servers WHERE subnet_id=$id");
    $cntSrv = ($cntRes && ($cntRow = $cntRes->fetch_assoc())) ? (int)$cntRow['c'] : 0;
    if ($cntSrv > 1) {
        // 2+ serveurs sans failover → shared (ne pas écraser 'cluster')
        $mysqli2->query("UPDATE subnets SET dhcp_topology='shared' WHERE id=$id AND dhcp_topology IS NULL");
    } elseif ($cntSrv <= 1) {
        // 0 ou 1 serveur → pas de topologie multi-serveur (ne pas écraser 'cluster')
        $mysqli2->query("UPDATE subnets SET dhcp_topology=NULL WHERE id=$id AND dhcp_topology='shared'");
    }
}

// Supprimer les baux des serveurs qui ne sont plus liés à ce subnet
$mysqli2->query("
    DELETE FROM dhcp_leases
    WHERE subnet_id = $id
      AND dhcp_server_id NOT IN (
          SELECT dhcp_server_id FROM subnet_dhcp_servers WHERE subnet_id = $id
      )
");

// Supprimer de ip_addresses les IPs DHCP de ce subnet sans bail restant
$mysqli2->query("
    DELETE FROM ip_addresses
    WHERE subnet_id = $id
      AND host_net_config = 'DHCP'
      AND NOT EXISTS (
          SELECT 1 FROM dhcp_leases dl
          WHERE dl.ip_address COLLATE utf8mb4_general_ci = ip_addresses.ip_address
            AND dl.subnet_id = $id
      )
");

echo json_encode(['ok' => true, 'id' => $id]);
