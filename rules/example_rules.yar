rule Suspicious_PHP_In_Image
{
    strings:
        $php = "<?php"
        $eval = "eval("
    condition:
        any of them
}
