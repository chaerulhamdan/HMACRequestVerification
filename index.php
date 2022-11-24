<?php

if (isset($_POST['username']) && isset($_POST['password'])) { //check jika body request username & password ada/terisi
    $secret = $_POST['password']; //saya menggunakan secret key untuk hmac nya dari password yang dimasukan user
    $payload = "";
    $headers = "";
    $signature = "";
    $result = false;
    try {
        $payload = file_get_contents('php://input'); //payload untuk mengambil body request
        $headers = getHeadersHTTP(); //ini untuk menampung header pada request HTTP function nya ada dibawah
        //print_r($headers);
        $url = "http://" . $_SERVER["HTTP_HOST"]  . $_SERVER["REQUEST_URI"].'|'. $payload;
        //echo $url;
        $hmac = hash_hmac('sha256', $url, utf8_encode($secret)); 
        //echo $hmac;
        //lalu saya buat url nya dengan format seperti diatas, $_SERVER["HTTP_HOST"] untuk mengambil host
        //contoh localhost:8000 dan $_SERVER["REQUEST_URI"] untuk mengambil url yang dituju contoh index.php
        //jadi nanti raw checksum urlnya menjadi http://localhost/index.php|username=ao&password=1234
        if (array_key_exists("XRequestVerification", $headers)) { //nah disini apabila pada header ada key yang bernama XRequestVerification
            $signature = $headers["XRequestVerification"];
            //di Header XRequestVerification ini kita memasukan hmac dari raw string url yang sudah di ubah ke base64Hash
            //$hmac = hash_hmac('sha256', $url, utf8_encode($secret)); //lalu kita ubah raw checksum string url menjadi hmac
            //menggunakan hash_hmac dengan algoritma sha256, lalu secret nya tadi saya memakai password
            //echo $hmac;
            if(hash_equals($signature,$hmac)){ 
                //lalu kita cek apakah hmac dari raw checksum string url sama dengan
                //value yang disimpan pada header HTTP, apabila sama/true kita tampislan Verification OK dengan json_encode supaya menjadi format json
                echo json_encode('Verification OK');
            } else {
                //jika tidak maka tampilkan Request Verification Failed
                echo json_encode('Request Verification Failed');
            }
        }
     } catch (Exception $e) {
        echo json_encode('data error');
    }
    //header("HTTP/1.1 200 OK");
}
 
    function getHeadersHTTP() //ini adalah function untuk mengambil data header pada HTTP
    {
        $headers = array(); //set header sebagai array
        //print_r($_SERVER);
        foreach ($_SERVER as $key => $value) { //lalu foreach looping sebanyak data $_SERVER
            if (strpos($key, 'HTTP_') === 0) { //hanya ambil data pada $_SERVER yang awalanya HTTP_
                $headers[str_replace(' ', '', ucwords(str_replace('_', ' ', strtolower(substr($key, 5)))))] = $value;
                //lalu kita hanya masukan content HTTP nya sebagai key dan masukan juga value nya
                //contoh apabila HTTP_HOST => localhost:8000
                //maka hanya dia mengambil HOST nya saja tetapi
                //dengan mengganti _ menjadi space dan mengganti space menjadi kosong
                //jadi apabila X-REQUEST akan menjadi XREQUEST
                //lalu kita ubah jadi huruf kecil semua dan menggunakan ucwords untuk menjadikan huruf pertama kapital
                //jadinya akan seperti XRequest
            }
        }
        return $headers;
    }
?>