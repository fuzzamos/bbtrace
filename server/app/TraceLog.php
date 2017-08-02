<?php

namespace App;

use Serializable;
use Closure;

class TraceLog implements Serializable
{
    private $data;

    private $name;
    private $log_count;

    public $blocks;
    public $symbols;
    public $modules;
    public $imports;
    public $exceptions;
    public $functions;
    public $callbacks;

    const PKT_CODE_TRACE = 1;

    public function __construct($fname)
    {
        $fname = realpath($fname);

        if (preg_match('/^(.+\.log)\.(info|[0-9]+|func)$/', $fname, $matches)) {
            $fname = $matches[1];
        } else {
            throw new Exception("File name error: $fname");
        }

        $this->data = (object)[
            'blocks' => [],
            'symbols' => [],
            'modules' => [],
            'imports' => [],
            'exceptions' => [],
            'functions' => [],
            'callbacks' => [],
            'name' => $fname,
            'paging' => null,
        ];

        $this->blocks = &$this->data->blocks;
        $this->symbols = &$this->data->symbols;
        $this->modules = &$this->data->modules;
        $this->imports = &$this->data->imports;
        $this->exceptions = &$this->data->exceptions;
        $this->functions = &$this->data->functions;
        $this->callbacks = &$this->data->callbacks;
        $this->name = &$this->data->name;
    }

    public function getLogCount()
    {
        if (!isset($this->log_count)) {
            $log_count = 0;
            for (;;$log_count++) {
                $fpath = sprintf("%s.%04d", $this->name, $log_count+1);
                if (!is_file($fpath)) break;
            }
            $this->log_count = $log_count;
        }
        return $this->log_count;
    }

    public function buildPaging()
    {
        $this->data->paging = [];

        for ($log_nbr=1; $log_nbr <= $this->getLogCount(); $log_nbr++) {
            $fpath = sprintf("%s.%04d", $this->name, $log_nbr);
            $fp = fopen($fpath, 'rb');

            while (!feof($fp)) {
                $pos = ftell($fp);
                $data = fread($fp, (4+8+4));
                if (!feof($fp)) {
                    $data = unpack('Lcode/Qts/Lthread', $data);
                } else break;

                if ($data['code'] == self::PKT_CODE_TRACE) {

                    $this->data->paging[] = [$log_nbr, $pos];

                    $data = unpack('Lsize', fread($fp, 4));
                    fseek($fp, $data['size']*4, SEEK_CUR);
                }
            }

            fclose($fp);
        }
    }

    /* callback return non zero to stop */
    public function parseLog($pkt_start, $pkt_stop, $callback)
    {
        if (! isset($this->data->paging)) $this->buildPaging();

        if (is_null($pkt_stop)) $pkt_stop = count($this->data->paging);

        for ($pkt_no = $pkt_start; $pkt_no < $pkt_stop; $pkt_no++) {
            $paging = $this->data->paging[ $pkt_no ];

            $fpath = sprintf("%s.%04d", $this->name, $paging[0]);
            //fprintf(STDERR, "Open: %s\n", $fpath);

            $fp = fopen($fpath, 'rb');
            $ret = null;
            fseek($fp, $paging[1], SEEK_CUR);

            if (feof($fp)) break;

            $data = fread($fp, (4+8+4));

            if (feof($fp)) break;

            $data = unpack('Lcode/Qts/Lthread', $data);

            if ($data['code'] == self::PKT_CODE_TRACE) {
                $header = array_merge($data, unpack('Lsize', fread($fp, 4)));

                $header['pkt_no'] = $pkt_no;

                $raw_data = fread($fp, $header['size']*4);
                $ret = $callback($header, $raw_data);

                if ($ret) break;
            }

            fclose($fp);
        }

        return $ret;
    }

    protected function saveInfo($o)
    {
        foreach(['block_entry', 'block_end', 'symbol_entry',
            'module_start_ref', 'module_start', 'module_end', 'module_entry',
            'exception_code', 'exception_address', 'fault_address',
            'function_entry', 'function_end',
        ] as $k) {
            if (isset($o[$k]) && is_string($o[$k]) && strpos($o[$k], '0x') === 0) {
                $o[$k] = hexdec($o[$k]);
            }
        }

        if (isset($o['module_start'])) {
            $this->modules[ $o['module_start'] ] = $o;
        } elseif (isset($o['block_entry'])) {
            $this->blocks[ $o['block_entry'] ] = $o;
        }
        elseif (isset($o['symbol_entry'])) {
            $this->symbols[ $o['symbol_entry'] ] = $o;
        }
        elseif (isset($o['exception_code'])) {
            $this->exceptions[ $o['exception_address'] ] = $o;
        }
        elseif (isset($o['import_module_name'])) {
            $this->imports[ $o['symbol_name'] ] = $o;
        }
        elseif (isset($o['function_entry'])) {
            $this->functions[ $o['function_entry'] ] = $o;
        }
        else {
            fprintf(STDERR, "Bad Info:%s\n", json_encode($o));
        }
    }

    public static function parseJson($fpath, Closure $save_cb)
    {
        fprintf(STDERR, "Open: %s\n", $fpath);

        $fp = fopen($fpath, 'r');
        $STATE_ARRAY = false;
        $STATE_OBJECT = false;
        $s = null;

        while (!feof($fp)) {
            $data = fgets($fp);
            $data = preg_replace('/\r\n/', '', $data);

            if ($STATE_OBJECT) {
                $s .= $data;
                if (preg_match('/\},?$/', $data)) {
                    $STATE_OBJECT = false;

                    $s = trim($s, "\r\n, ");
                    $o = json_decode($s, true);
                    if (!empty($o)) {
                        $save_cb($o);
                    }
                }
            } elseif ($STATE_ARRAY) {
                if (preg_match('/^\{/', $data)) {
                    $STATE_OBJECT = true;
                    $s = $data;
                }
                if ($STATE_OBJECT && preg_match('/\},?$/', $data)) {
                    $STATE_OBJECT = false;

                    $s = trim($s, "\r\n, ");
                    $o = json_decode($s, true);
                    if (!empty($o)) {
                        $save_cb($o);
                    }
                }
                if (preg_match('/\],?$/', $data)) {
                    $STATE_ARRAY = false;
                }
            } else {
                if (preg_match('/^\[/', $data)) {
                    $STATE_ARRAY = true;
                }
                if ($STATE_ARRAY && preg_match('/\],?$/', $data)) {
                    $STATE_ARRAY = false;
                }
            }
        }

    }

    public function parseInfo()
    {
        $fpath = sprintf("%s.info", $this->name);
        self::parseJson($fpath, function($o) {
            $this->saveInfo($o);
        });
    }

    public function parseFunc()
    {
        $fpath = sprintf("%s.func", $this->name);
        self::parseJson($fpath, function($o) {
            $this->saveInfo($o);
        });
    }

    public function serialize(): string
    {
        return serialize($this->data);
    }

    public function unserialize($serialized)
    {
        $this->data = unserialize($serialized);

        $this->blocks = &$this->data->blocks;
        $this->symbols = &$this->data->symbols;
        $this->modules = &$this->data->modules;
        $this->imports = &$this->data->imports;
        $this->exceptions = &$this->data->exceptions;
        $this->functions = &$this->data->functions;
        $this->callbacks = &$this->data->callbacks;
        $this->name = &$this->data->name;
    }

    public function __toString()
    {
        $output = sprintf("Name: %s\n", $this->name);
        $output.= sprintf("Blocks: %d\n", count($this->blocks));
        $output.= sprintf("Symbols: %d\n", count($this->symbols));
        $output.= sprintf("Modules: %d\n", count($this->modules));
        $output.= sprintf("Imports: %d\n", count($this->imports));
        $output.= sprintf("Exceptions: %d\n", count($this->exceptions));
        $output.= sprintf("Functions: %d\n", count($this->functions));
        $output.= sprintf("Callbacks: %d\n", count($this->callbacks));
        $output.= sprintf("Count: %d\n", $this->getLogCount());

        return $output;
    }

}
