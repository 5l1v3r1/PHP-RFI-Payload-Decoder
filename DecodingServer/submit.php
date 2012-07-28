<?php
/*
 * Generates a name for a bot dump
 * Set $dumpFolder to a folder that is not web viewable, its suggested to use the full path
 *
 * returns false if it already exists, else returns the filename
 */
function GetFileName($uri, $tail = "", $canFail = true)
{
    $dumpFolder = "temp/";
    if(file_exists($dumpFolder.md5($uri).$tail))
    {
        if($canFail)
            return false;
    }
    return $dumpFolder.md5($uri).$tail;
}

function GetUrl($uri)
{
    return "https://www.firebwall.com/decoding/read.php?u=".md5($uri);
}

function RemoveComments($str)
{
        $done = false;
        while($done === false)
        {
                if(preg_match('/\/\*.*\*\//m', $str, $matches))
                {
                    $str = str_replace($matches[0], "", $str);
                }
                else
                {
                        $done = true;
                }
        }
        return $str;
}

function ExpandLines($str)
{
    return $str;
}

function ClearEmptyEvals(&$str)
{
    $done = false;
    while($done === false)
    {
        if(preg_match('/eval\(["\'][[:space:]]*["\']\);/m', $str, $matches))
        {
                $str = str_replace($matches[0], "", $str);
        }
        else
                $done = true;
    }
}

function Decode($funcArray, &$str, &$aliases, &$steps)
{
        $count = count($funcArray);
        $funcs = "";
        $tail = "";
        $toEval = "";
        $endEval = "";
        for($i = 0; $i < $count; $i++)
        {
                $funcs .= $funcArray[$i]."[[:space:]]*\([[:space:]]*";
                $tail .= '[[:space:]]*\)';
                $toEval .= $funcArray[$i]."(";
                $endEval .= ")";
        }
        $endEval .= ";";
        if(preg_match('/'.$funcs.'(?<data>"[^"]+")'.$tail.'/m', $str, $matches))
        {
                $str = str_replace($matches[0], "'".ExpandLines(eval("return ".$toEval.$matches["data"].$endEval))."'", $str);
                $steps .= $toEval.$matches["data"].$endEval."\n";
                return true;
        }
        else if(preg_match('/'.$funcs.'(?<data>\'[^\']+\')'.$tail.'/m', $str, $matches))
        {
                $str = str_replace($matches[0], "'".ExpandLines(eval("return ".$toEval.$matches["data"].$endEval))."'", $str);
                $steps .= $toEval.$matches["data"].$endEval."\n";
                return true;
        }
        else if(preg_match('/'.$funcs.'(?<data>\'[^\']+\')/m', $str, $matches))
        {
                $str = str_replace($matches[0], "'".ExpandLines(eval("return ".$toEval.$matches["data"].$endEval))."'", $str);
                $steps .= $toEval.$matches["data"].$endEval."\n";
                return true;
        }
        else if(preg_match('/'.$funcs.'(?<data>"[^"]+")/m', $str, $matches))
        {
                $str = str_replace($matches[0], "'".ExpandLines(eval("return ".$toEval.$matches["data"].$endEval))."'", $str);
                $steps .= $toEval.$matches["data"].$endEval."\n";
                return true;
        }
        else if(preg_match('/'.$funcs.'(?<data>"[^"]+)/m', $str, $matches))
        {
                $str = str_replace($matches[0], "'".ExpandLines(eval("return ".$toEval.$matches["data"].'"'.$endEval))."'", $str);
                $steps .= $toEval.$matches["data"].$endEval."\n";
                return true;
        }
        else if(preg_match('/'.$funcs.'(?<data>\'[^\']+)/m', $str, $matches))
        {
                $str = str_replace($matches[0], "'".ExpandLines(eval("return ".$toEval.$matches["data"]."'".$endEval))."'", $str);
                $steps .= $toEval.$matches["data"].$endEval."\n";
                return true;
        }
        else
        {
                return false;
        }

}

function RemoteFileSize($url)
{
        $sch = parse_url($url, PHP_URL_SCHEME);
        if (($sch != "http") && ($sch != "https") && ($sch != "ftp") && ($sch != "ftps")) {
            return false;
        }
        if (($sch == "http") || ($sch == "https")) {
            $headers = get_headers($url, 1);
            if ((!array_key_exists("Content-Length", $headers))) { return false; }
            return $headers["Content-Length"];
        }
        if (($sch == "ftp") || ($sch == "ftps")) {
            $server = parse_url($url, PHP_URL_HOST);
            $port = parse_url($url, PHP_URL_PORT);
            $path = parse_url($url, PHP_URL_PATH);
            $user = parse_url($url, PHP_URL_USER);
            $pass = parse_url($url, PHP_URL_PASS);
            if ((!$server) || (!$path)) { return false; }
            if (!$port) { $port = 21; }
            if (!$user) { $user = "anonymous"; }
            if (!$pass) { $pass = "phpos@"; }
            switch ($sch) {
                case "ftp":
                    $ftpid = ftp_connect($server, $port);
                    break;
                case "ftps":
                    $ftpid = ftp_ssl_connect($server, $port);
                    break;
            }
            if (!$ftpid) { return false; }
            $login = ftp_login($ftpid, $user, $pass);
            if (!$login) { return false; }
            $ftpsize = ftp_size($ftpid, $path);
            ftp_close($ftpid);
            if ($ftpsize == -1) { return false; }
            return $ftpsize;
        }
}

function AutoDecode(&$str, &$steps)
{
    $str = RemoveComments($str);
    $str = ExpandLines($str);
    $done = FALSE;
    $aliases = array();
    $variables = array();
    while($done === FALSE)
    {
        if(Decode(array("gzinflate", "str_rot13", "base64_decode"), $str, $aliases, $steps) ||
                    Decode(array("gzuncompress", "str_rot13", "base64_decode"), $str, $aliases, $steps) ||
                    Decode(array("gzinflate", "str_rot13"), $str, $aliases, $steps) ||
                    Decode(array("gzuncompress", "str_rot13"), $str, $aliases, $steps) ||
                    Decode(array("gzinflate", "base64_decode"), $str, $aliases, $steps) ||
                    Decode(array("gzuncompress", "base64_decode"), $str, $aliases, $steps) ||
                    Decode(array("base64_decode"), $str, $aliases, $steps) ||
                    Decode(array("gzinflate", "str_rot13"), $str, $aliases, $steps) ||
                    Decode(array("gzinflate", "base64_decode", "str_rot13"), $str, $aliases, $steps) ||
                    Decode(array("base64_decode", "str_rot13"), $str, $aliases, $steps))
        {
        }
        else
        {
            $done = true;
            if(preg_match_all('/(\$[[:alnum:]_]+)[[:space:]]*=[[:space:]]*("[^"]+");/s', $str, $matches) != 0)
            {
                $count = count($matches[0]);
                for($i = 0; $i < $count; $i++)
                {
                    $name = $matches[1][$i];
                    if(in_array($name, $variables) === true)
                    {
                        continue;
                    }
                    $value = $matches[2][$i];
                    if($str !== preg_replace('/('.preg_quote($name).')([^<>[:alnum:]_ \=])/m', "$value$2", $str) && strstr($value, $name) === false)
                    {
                        $done = false;
                        array_push($variables, $name);
                        $str = preg_replace('/('.preg_quote($name).')([^<>[:alnum:]_ \=])/m', "$value$2", $str);
                        $steps .= "Replacing $name with $value\n";
                    }
                }
            }
            if(preg_match_all('/(\$[[:alnum:]_]+)[[:space:]]*=[[:space:]]*(\'[^\']+\');/s', $str, $matches) != 0)
            {
                $count = count($matches[0]);
                for($i = 0; $i < $count; $i++)
                {
                    $name = $matches[1][$i];
                    if(in_array($name, $variables) === true)
                    {
                        continue;
                    }
                    $value = $matches[2][$i];
                    if($str !== preg_replace('/('.preg_quote($name).')([^<>[:alnum:]_ \=])/m', "$value$2", $str) && strstr($value, $name) === false)
                    {
                        $done = false;
                        array_push($variables, $name);
                        $str = preg_replace('/('.preg_quote($name).')([^<>[:alnum:]_ \=])/m', "$value$2", $str);
                        $steps .= "Replacing $name with $value\n";
                    }
                }
            }
        }

        ClearEmptyEvals($str);
    }
}
$str = "";
$steps = "";
$meta = "";
if(isset($_GET['u']) && !empty($_GET['u']))
{
    $url = base64_decode(urldecode($_GET['u']));
    $file = GetFileName($url, ".DecodedByUrl");
    if($file !== false)
    {
        $fileSize = RemoteFileSize($url);
        if($fileSize !== false && $fileSize < (1024 * 1024  * 16))
        {
            $str = file_get_contents($url, false);
	    $raw = $str;
            if($str !== false)
            {
                AutoDecode($str, $steps);
                $toFile = "Timestamp: ".strftime('%c')."\n";
                $toFile .= "URL: ".$url."\n";
                $toFile .= "Was decoded from url on server.\n\n";
                $toFile .= "Shell -> ".base64_encode($str)."\n\n";
				$toFile .= "Raw -> ".base64_encode($raw)."\n\n";
                file_put_contents($file, $toFile);
            }
        }
    }
}
?>
