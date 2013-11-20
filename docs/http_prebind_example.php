<?php 

error_reporting(-1);
/* Settings */
/* Prebind address */
$url = 'http://localhost:5280/http-bind';
/* Usually the Realm */
$domain = 'example.com';
$timeout = 3;
/* The user you want to login for this session.
Anonymous sessions are not supported */
$loginuser = 'testusertologin';
/* The resource for this user */
$resource = 'www';
/* The secret prebind_token.
Never transfer it over an unsecured connection */
$password = 'MyPrebind_PASS123';




mt_srand();
$rid = mt_rand(1, 0xEEEEEEEE);


$data = "<body "
            ."hold=\"1\" "
            ."rid=\"".$rid."\" "
            ."to=\"".$domain."\" "
            ."ver=\"1.6\" "
            ."wait=\"30\" "
            ."ack=\"1\" "
            ."xml:lang=\"en\" "
            ."xmpp:version=\"1.0\" "
            ."xmlns:xmpp=\"urn:xmpp:xbosh\" "
            ."xmlns=\"http://jabber.org/protocol/httpbind\" "
            ."prebind_resource=\"".$resource."\" "
            ."prebind_username=\"".$loginuser."\" "
            ."prebind_token=\"".base64_encode($password)."\""
        ."/>";

// use key 'http' even if you send the request to https://...
$options = array(
    'http' => array(
                'header'  => "Content-type: text/xml\r\n",
                'method'  => 'POST',
                'timeout' => $timeout,
                'content' => $data),
    );


$context  = stream_context_create($options);
$result = file_get_contents($url, false, $context);

$prebind_succeeded = FALSE;

if($result !== FALSE)
{

    $xml = simplexml_load_string($result);
    if($xml !== FALSE)
    {
        $attr = $xml->Attributes();

        $sid = $attr->sid;
        $jid = $loginuser.'@'.$domain;

        if(isset($sid))
            $prebind_succeeded = TRUE;
    }
}

?>


<?php
    if($prebind_succeeded)
    {
        echo "sid: ".$sid." ";
        echo "jid: ".$jid." ";
        echo "rid: ".$rid." ";
    }else{

        echo "Failure to prebind session!";
    }
?>