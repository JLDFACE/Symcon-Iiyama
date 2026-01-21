<?php

class IiyamaDisplayConfigurator extends IPSModule
{
    public function Create()
    {
        parent::Create();

        $this->RegisterPropertyString('ScanSubnet', $this->GetDefaultScanSubnet());
        $this->RegisterPropertyInteger('Port', 5000);
        $this->RegisterPropertyInteger('Timeout', 500);

        $this->RegisterPropertyString('ManualIP', '');
        $this->RegisterPropertyInteger('ManualPort', 5000);

        $this->RegisterAttributeString('Discovered', '[]');
    }

    public function ApplyChanges()
    {
        parent::ApplyChanges();
        $this->SetStatus(102);
    }

    public function GetConfigurationForm()
    {
        $form = json_decode(file_get_contents(__DIR__ . '/form.json'), true);
        if (!is_array($form)) $form = array();

        $values = json_decode($this->ReadAttributeString('Discovered'), true);
        if (!is_array($values)) $values = array();

        if (!isset($form['actions']) || !is_array($form['actions'])) $form['actions'] = array();

        for ($i = 0; $i < count($form['actions']); $i++) {
            if (isset($form['actions'][$i]['type']) && $form['actions'][$i]['type'] == 'Configurator'
                && isset($form['actions'][$i]['name']) && $form['actions'][$i]['name'] == 'DeviceList') {
                $form['actions'][$i]['values'] = $values;
            }
        }

        $configured = trim($this->ReadPropertyString('ScanSubnet'));
        $auto = $this->DetectLocalSubnet();
        $useAuto = false;
        if ($configured === '' || !$this->IsValidCIDR($configured)) {
            $useAuto = true;
        } elseif ($configured === '192.168.1.0/24' && $auto !== '' && $auto !== $configured) {
            $useAuto = true;
        }
        $effectiveSubnet = $useAuto ? $auto : $configured;
        if ($effectiveSubnet !== '' && isset($form['elements']) && is_array($form['elements'])) {
            for ($i = 0; $i < count($form['elements']); $i++) {
                if (isset($form['elements'][$i]['name']) && $form['elements'][$i]['name'] == 'ScanSubnet') {
                    $form['elements'][$i]['value'] = $effectiveSubnet;
                    continue;
                }
                if (isset($form['elements'][$i]['items']) && is_array($form['elements'][$i]['items'])) {
                    for ($j = 0; $j < count($form['elements'][$i]['items']); $j++) {
                        if (isset($form['elements'][$i]['items'][$j]['name']) && $form['elements'][$i]['items'][$j]['name'] == 'ScanSubnet') {
                            $form['elements'][$i]['items'][$j]['value'] = $effectiveSubnet;
                        }
                    }
                }
            }
        }

        return json_encode($form);
    }

    public function Scan()
    {
        IPS_LogMessage('IIYAMA CFG', 'Scan() gestartet, Instanz ' . $this->InstanceID);
        $this->SendDebug('IIYAMA CFG', 'Scan() gestartet, Instanz ' . $this->InstanceID, 0);

        $subnet = $this->GetEffectiveScanSubnet();
        $port = (int)$this->ReadPropertyInteger('Port');
        if ($subnet === '') {
            IPS_LogMessage('IIYAMA CFG', 'Scan abgebrochen: kein gueltiges Subnetz ermittelt.');
            $this->SendDebug('IIYAMA CFG', 'Scan abgebrochen: kein gueltiges Subnetz ermittelt.', 0);
            return;
        }

        $ips = $this->ExpandCIDR($subnet, 2048);
        $this->SendDebug('IIYAMA CFG', 'Subnetz=' . $subnet . ' Port=' . $port . ' IPs=' . count($ips), 0);
        $found = array();

        foreach ($ips as $ip) {
            $probe = $this->ProbeDevice($ip, $port);
            if ($probe['ok']) {
                $found[] = array(
                    'IP' => $ip,
                    'Port' => $port,
                    'Model' => $probe['model'],
                    'Firmware' => $probe['firmware']
                );
                $this->SendDebug('IIYAMA CFG', 'Gefunden: ' . $ip . ' ' . $probe['model'], 0);
            }
        }

        $values = $this->BuildValues($found);
        $this->WriteAttributeString('Discovered', json_encode($values));
        $this->UpdateFormField('DeviceList', 'values', $values);
        IPS_LogMessage('IIYAMA CFG', 'Scan beendet, gefunden: ' . count($found));
        $this->SendDebug('IIYAMA CFG', 'Scan beendet, gefunden: ' . count($found), 0);
    }

    public function AddManual()
    {
        $ip = trim($this->ReadPropertyString('ManualIP'));
        $port = (int)$this->ReadPropertyInteger('ManualPort');

        if ($ip === '') {
            echo 'Fehler: IP-Adresse darf nicht leer sein.';
            return;
        }

        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            echo 'Fehler: Ungueltige IP-Adresse.';
            return;
        }

        $probe = $this->ProbeDevice($ip, $port);
        if (!$probe['ok']) {
            echo 'Fehler: Geraet unter ' . $ip . ':' . $port . ' nicht erreichbar oder nicht kompatibel.';
            return;
        }

        $existing = json_decode($this->ReadAttributeString('Discovered'), true);
        if (!is_array($existing)) $existing = array();

        foreach ($existing as $item) {
            if (isset($item['IP']) && $item['IP'] === $ip) {
                echo 'Info: Geraet ' . $ip . ' ist bereits in der Liste.';
                return;
            }
        }

        $newDevice = array(
            'IP' => $ip,
            'Port' => $port,
            'Model' => $probe['model'],
            'Firmware' => $probe['firmware']
        );

        $newRows = $this->BuildValues(array($newDevice));
        foreach ($newRows as $row) {
            $existing[] = $row;
        }

        $this->WriteAttributeString('Discovered', json_encode($existing));
        $this->UpdateFormField('DeviceList', 'values', $existing);
        echo 'Erfolg: Geraet ' . $ip . ' (' . $probe['model'] . ') wurde hinzugefuegt.';
    }

    private function BuildValues($foundDevices)
    {
        $deviceModuleID = '{F10FBBAA-0FAF-4039-AFE6-962F7A172213}';
        $values = array();

        foreach ($foundDevices as $row) {
            $ip = isset($row['IP']) ? (string)$row['IP'] : '';
            $port = isset($row['Port']) ? (int)$row['Port'] : (int)$this->ReadPropertyInteger('Port');
            $model = isset($row['Model']) ? (string)$row['Model'] : '';
            $firmware = isset($row['Firmware']) ? (string)$row['Firmware'] : '';

            $existing = $this->FindInstanceByHost($deviceModuleID, $ip);

            $rowOut = array(
                'IP' => $ip,
                'Model' => $this->TrimBraces($model),
                'Firmware' => $this->TrimBraces($firmware),
                'Port' => $port,
                'instanceID' => ($existing > 0) ? $existing : 0
            );

            if ($existing == 0) {
                $name = ($model !== '') ? $model : $ip;
                $rowOut['create'] = array(
                    'moduleID' => $deviceModuleID,
                    'name' => $name,
                    'configuration' => array(
                        'Host' => $ip,
                        'Port' => $port
                    )
                );
            }

            $values[] = $rowOut;
        }

        return $values;
    }

    private function ProbeDevice($ip, $port)
    {
        $timeoutMs = (int)$this->ReadPropertyInteger('Timeout');
        if ($timeoutMs < 100) $timeoutMs = 100;

        $model = $this->GetLabel($ip, $port, $timeoutMs, 1);
        $firmware = $this->GetLabel($ip, $port, $timeoutMs, 0);

        if ($model === '' && $firmware === '') {
            $power = $this->GetPower($ip, $port, $timeoutMs);
            if ($power === false) {
                return array('ok' => false);
            }
        }

        return array(
            'ok' => true,
            'model' => $model,
            'firmware' => $firmware
        );
    }

    private function GetPower($ip, $port, $timeoutMs)
    {
        $rep = $this->SendGetCommand($ip, $port, $timeoutMs, 0x19, array());
        if ($rep === false) return false;
        if (!isset($rep['data'][1])) return false;
        $state = (int)$rep['data'][1];
        if ($state == 0x02 || $state == 0x01) return $state;
        return false;
    }

    private function GetLabel($ip, $port, $timeoutMs, $which)
    {
        $w = (int)$which;
        if ($w != 0 && $w != 1) $w = 0;

        $rep = $this->SendGetCommand($ip, $port, $timeoutMs, 0xA2, array($w));
        if ($rep === false) return '';

        $bytes = array();
        $i = 1;
        while (isset($rep['data'][$i])) {
            $bytes[] = chr((int)$rep['data'][$i]);
            $i++;
        }
        return trim(implode('', $bytes));
    }

    private function SendGetCommand($host, $port, $timeoutMs, $cmd, $dataTail)
    {
        $packet = $this->BuildPacket(0xA6, (int)$cmd, $dataTail);
        $resp = $this->SendAndReceive($host, $port, $timeoutMs, $packet);
        if ($resp === false) return false;
        if ($resp['header'] != 0x21) return false;
        if (!isset($resp['data'][0])) return false;
        return $resp;
    }

    private function BuildPacket($header, $cmd, $dataTail)
    {
        $id = 1;
        $data = array();
        $data[] = (int)$cmd;

        if (is_array($dataTail)) {
            foreach ($dataTail as $b) {
                $data[] = (int)$b;
            }
        }

        $len = count($data) + 3;

        $bytes = array(
            (int)$header,
            $id,
            0x00,
            0x00,
            0x00,
            $len,
            0x01
        );

        foreach ($data as $b) {
            $bytes[] = $b;
        }

        $chk = 0x00;
        foreach ($bytes as $b) {
            $chk = $chk ^ ($b & 0xFF);
        }
        $bytes[] = $chk & 0xFF;

        $out = '';
        foreach ($bytes as $b) {
            $out .= chr($b & 0xFF);
        }
        return $out;
    }

    private function SendAndReceive($host, $port, $timeoutMs, $binaryPacket)
    {
        if ($timeoutMs < 100) $timeoutMs = 100;
        $timeoutSec = $timeoutMs / 1000.0;

        $errno = 0;
        $errstr = '';
        $fp = @fsockopen($host, (int)$port, $errno, $errstr, $timeoutSec);
        if (!$fp) {
            return false;
        }

        stream_set_timeout($fp, (int)$timeoutSec, (int)(($timeoutSec - (int)$timeoutSec) * 1000000));

        $len = strlen($binaryPacket);
        $written = 0;
        while ($written < $len) {
            $w = @fwrite($fp, substr($binaryPacket, $written));
            if ($w === false || $w === 0) {
                @fclose($fp);
                return false;
            }
            $written += $w;
        }

        $hdr = $this->ReadBytes($fp, 5);
        if ($hdr === false || strlen($hdr) < 5) {
            @fclose($fp);
            return false;
        }

        $msglen = ord($hdr[4]);
        $rest = $this->ReadBytes($fp, $msglen);
        @fclose($fp);

        if ($rest === false || strlen($rest) < $msglen) {
            return false;
        }

        $packet = $hdr . $rest;
        $parsed = $this->ParseResponse($packet);
        if ($parsed === false) {
            return false;
        }

        return $parsed;
    }

    private function ReadBytes($fp, $len)
    {
        $data = '';
        $remaining = (int)$len;

        while ($remaining > 0) {
            $chunk = @fread($fp, $remaining);
            if ($chunk === false) {
                return false;
            }
            if ($chunk === '') {
                $meta = stream_get_meta_data($fp);
                if (isset($meta['timed_out']) && $meta['timed_out']) {
                    return false;
                }
                break;
            }
            $data .= $chunk;
            $remaining = $len - strlen($data);
        }

        return $data;
    }

    private function ParseResponse($binary)
    {
        if (strlen($binary) < 7) return false;

        $header = ord($binary[0]);
        $id = ord($binary[1]);
        $category = ord($binary[2]);
        $page = ord($binary[3]);
        $msglen = ord($binary[4]);

        $totalLen = 5 + $msglen;
        if (strlen($binary) != $totalLen) {
            return false;
        }

        $chk = 0x00;
        for ($i = 0; $i < $totalLen - 1; $i++) {
            $chk = $chk ^ ord($binary[$i]);
        }
        $chk = $chk & 0xFF;

        $recvChk = ord($binary[$totalLen - 1]) & 0xFF;
        if ($chk != $recvChk) {
            return false;
        }

        $control = ord($binary[5]);
        $dataBytes = array();
        $dataLen = $msglen - 2;
        for ($i = 0; $i < $dataLen; $i++) {
            $dataBytes[$i] = ord($binary[6 + $i]) & 0xFF;
        }

        return array(
            'header'   => $header,
            'id'       => $id,
            'category' => $category,
            'page'     => $page,
            'msglen'   => $msglen,
            'control'  => $control,
            'data'     => $dataBytes
        );
    }

    private function TrimBraces($value)
    {
        $value = trim((string)$value);
        if (strlen($value) >= 2 && $value[0] == '{' && substr($value, -1) == '}') {
            return trim(substr($value, 1, -1));
        }
        return $value;
    }

    private function ExpandCIDR($cidr, $limit)
    {
        $cidr = trim($cidr);
        $parts = explode('/', $cidr);
        if (count($parts) != 2) return array();

        $base = trim($parts[0]);
        $mask = (int)$parts[1];
        if ($mask < 0 || $mask > 32) return array();

        $baseLong = ip2long($base);
        if ($baseLong === false) return array();

        $hostBits = 32 - $mask;
        $count = 1 << $hostBits;
        if ($count < 0) $count = 0;

        if ($count > (int)$limit) $count = (int)$limit;

        $netLong = $baseLong & (-1 << $hostBits);

        $ips = array();
        for ($i = 1; $i < $count - 1; $i++) {
            $ips[] = long2ip($netLong + $i);
        }

        if (count($ips) == 0) $ips[] = $base;
        return $ips;
    }

    private function GetEffectiveScanSubnet()
    {
        $configured = trim($this->ReadPropertyString('ScanSubnet'));
        $auto = $this->DetectLocalSubnet();

        if ($configured === '' || !$this->IsValidCIDR($configured)) {
            return ($auto !== '') ? $auto : '';
        }

        if ($configured === '192.168.1.0/24' && $auto !== '' && $auto !== $configured) {
            return $auto;
        }

        return $configured;
    }

    private function GetDefaultScanSubnet()
    {
        $auto = $this->DetectLocalSubnet();
        if ($auto !== '') {
            return $auto;
        }
        return '192.168.1.0/24';
    }

    private function DetectLocalSubnet()
    {
        $entries = array();

        if (function_exists('Sys_GetNetworkInfo')) {
            $info = @Sys_GetNetworkInfo();
            $entries = array_merge($entries, $this->ExtractNetworkEntries($info));
        }
        if (function_exists('Sys_GetNetworkInfoEx')) {
            $info = @Sys_GetNetworkInfoEx();
            $entries = array_merge($entries, $this->ExtractNetworkEntries($info));
        }

        $best = '';
        foreach ($entries as $entry) {
            $cidr = $this->CidrFromEntry($entry);
            if ($cidr === '') continue;
            if ($this->EntryHasGateway($entry)) return $cidr;
            if ($best === '') $best = $cidr;
        }

        if ($best !== '') return $best;

        $fallbackIp = $this->GetFallbackIPv4();
        if ($fallbackIp !== '') {
            return $this->BuildCIDR($fallbackIp, '255.255.255.0', '');
        }

        return '';
    }

    private function ExtractNetworkEntries($info)
    {
        $entries = array();
        if (!is_array($info)) return $entries;

        if ($this->LooksLikeNetworkEntry($info)) {
            $entries[] = $info;
            return $entries;
        }

        foreach ($info as $entry) {
            if ($this->LooksLikeNetworkEntry($entry)) {
                $entries[] = $entry;
            }
        }
        return $entries;
    }

    private function LooksLikeNetworkEntry($entry)
    {
        if (!is_array($entry)) return false;
        $keys = array('IP', 'ip', 'Address', 'Addr', 'IPv4', 'IPv4Address', 'Host');
        foreach ($keys as $key) {
            if (isset($entry[$key])) return true;
        }
        return false;
    }

    private function EntryHasGateway($entry)
    {
        if (!is_array($entry)) return false;
        $keys = array('Gateway', 'gateway', 'IPv4Gateway');
        foreach ($keys as $key) {
            if (!isset($entry[$key])) continue;
            $gw = trim((string)$entry[$key]);
            if ($gw !== '' && $gw !== '0.0.0.0') return true;
        }
        return false;
    }

    private function CidrFromEntry($entry)
    {
        if (!is_array($entry)) return '';

        $ip = $this->FirstValue($entry, array('IP', 'ip', 'Address', 'Addr', 'IPv4', 'IPv4Address', 'Host'));
        $mask = $this->FirstValue($entry, array('Subnet', 'SubnetMask', 'Netmask', 'Mask', 'IPv4Mask'));
        $prefix = $this->FirstValue($entry, array('Prefix', 'PrefixLength', 'CIDR'));

        if ($ip === '') return '';
        if (strpos($ip, '/') !== false) {
            $parts = explode('/', $ip, 2);
            $ip = trim($parts[0]);
            if ($prefix === '') $prefix = trim($parts[1]);
        }

        return $this->BuildCIDR($ip, $mask, $prefix);
    }

    private function BuildCIDR($ip, $mask, $prefix)
    {
        if (!$this->IsUsableIPv4($ip)) return '';

        $prefix = trim((string)$prefix);
        if ($prefix === '' && $mask !== '') {
            if (strpos($mask, '.') !== false) {
                $prefix = (string)$this->NetmaskToCidr($mask);
            } else {
                $prefix = (string)(int)$mask;
            }
        }

        $prefixInt = (int)$prefix;
        if ($prefixInt < 0 || $prefixInt > 32) return '';

        $ipLong = ip2long($ip);
        if ($ipLong === false) return '';

        $hostBits = 32 - $prefixInt;
        $netLong = $ipLong & (-1 << $hostBits);
        return long2ip($netLong) . '/' . $prefixInt;
    }

    private function NetmaskToCidr($mask)
    {
        $maskLong = ip2long($mask);
        if ($maskLong === false) return -1;
        if ($maskLong < 0) $maskLong += 4294967296;

        $bin = decbin($maskLong);
        $bin = str_pad($bin, 32, '0', STR_PAD_LEFT);
        if (!preg_match('/^1*0*$/', $bin)) return -1;
        return substr_count($bin, '1');
    }

    private function IsValidCIDR($cidr)
    {
        $cidr = trim((string)$cidr);
        if ($cidr === '') return false;
        $parts = explode('/', $cidr);
        if (count($parts) != 2) return false;

        $ip = trim($parts[0]);
        $prefix = (int)trim($parts[1]);
        if (!$this->IsUsableIPv4($ip)) return false;
        return ($prefix >= 0 && $prefix <= 32);
    }

    private function IsUsableIPv4($ip)
    {
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) return false;
        if ($ip === '0.0.0.0') return false;
        if (strpos($ip, '127.') === 0) return false;
        if (strpos($ip, '169.254.') === 0) return false;
        return true;
    }

    private function FirstValue($entry, $keys)
    {
        foreach ($keys as $key) {
            if (isset($entry[$key]) && $entry[$key] !== '') {
                return (string)$entry[$key];
            }
        }
        return '';
    }

    private function GetFallbackIPv4()
    {
        $host = '';
        if (isset($_SERVER['SERVER_ADDR'])) {
            $host = (string)$_SERVER['SERVER_ADDR'];
        } else {
            $host = (string)gethostbyname(gethostname());
        }
        return $this->IsUsableIPv4($host) ? $host : '';
    }

    private function FindInstanceByHost($moduleID, $host)
    {
        $ids = IPS_GetInstanceListByModuleID($moduleID);
        foreach ($ids as $id) {
            $h = (string)IPS_GetProperty($id, 'Host');
            if ($h === $host) {
                return $id;
            }
        }
        return 0;
    }
}
