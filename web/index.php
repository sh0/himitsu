<?php

// Base64 lookup table
$s_b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz012345678901=";

// Posted variables
$hash_target = "";
$hash_master = "";
$hash_hash = "";
if (isset($_REQUEST['target']))
    $hash_target = $_REQUEST['target'];
if (isset($_REQUEST['master']))
    $hash_master = $_REQUEST['master'];

// Process only when both target and master variables are present
if (strlen($hash_target) && strlen($hash_master)) {
    // Calculate sha1(target) and sha1(master)
    $v_sha_target = unpack("C*", sha1($hash_target, TRUE));
    $v_sha_master = unpack("C*", sha1($hash_master, TRUE));
    
    // Calculate sha1(target) ^ sha1(master)
    $v_xor = array();
    for ($i = 1; $i <= count($v_sha_target); $i += 1)
        $v_xor[] = $v_sha_target[$i] ^ $v_sha_master[$i];
    
    // Calculate sha1(sha1(target) ^ sha1(master))
    $v_xor_str = "";
    foreach ($v_xor as &$r)
        $v_xor_str .= pack("c", $r); 
    $v_sha = unpack("C*", sha1($v_xor_str, TRUE));
    
    // Convert to base64
    $v_b64 = "";
    for ($i = 1; $i <= count($v_sha) - 2; $i += 3) {
        $t = $v_sha[$i] | ($v_sha[$i + 1] << 8) | ($v_sha[$i + 2] << 16);
        for ($j = 0; $j < 4; $j += 1) {
            $b = ($t & 0x3f);
            $t = ($t >> 6);
            $v_b64 .= $s_b64[$b];
        }
    }
    
    // Result is first 12 characters
    $hash_hash = substr($v_b64, 0, 12);
}

?><!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.1//EN" "http://www.w3.org/TR/xhtml11/DTD/xhtml11.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>

    <meta http-equiv="content-type" content="text/html; charset=UTF-8" />
    <title>ひみつ</title>
    <link rel="shortcut icon" href="http://yutani.ee/favicon.ico" />
    <style type="text/css">
        body {
            margin: 0px;
            color: #000000;
            font-size: 12px;
            font-family: calibri, verdana, sans;
            background-color: #eeeeee;
            background-image: url('back.jpg');
            background-repeat: no-repeat;
            background-attachment: fixed;
            background-position: top center;
        }
        
        input {
            border: 1px solid #000000;
            font-family: courier, verdana, sans;
            font-size: 12px;
            background-color: rgba(255,255,255, 0.1);
        }
        fieldset {
            border: 0px;
            margin: 0px;
            padding: 0px;
        }
        
        #title {
            text-align: center;
            font-size: 60px;
            font-weight: bold;
            width: 200px;
            background-color: rgba(255,255,255, 0.6);
            padding: 10px;
            margin-top: 10px;
            margin-left: 10px;
        }
        
        #main {
            text-align: center;
            font-size: 12px;
            width: 200px;
            background-color: rgba(255,255,255, 0.6);
            padding: 10px;
            margin-top: 10px;
            margin-left: 10px;
        }
    </style>
    <script type="text/javascript">//<![CDATA[
        function js_sha1(msg) {
         
            function rol32(n,s) {
                var t = (n << s) | (n >>> (32-s));
                return t;
            };
         
            var blockstart;
            var i, j;
            var W = new Array(80);
            var H0 = 0x67452301;
            var H1 = 0xEFCDAB89;
            var H2 = 0x98BADCFE;
            var H3 = 0x10325476;
            var H4 = 0xC3D2E1F0;
            var A, B, C, D, E;
         
            // Convert to int array
            var msg_len = msg.length;
            var word_array = new Array();
            for( i=0; i<msg_len-3; i+=4 ) {
                j = (msg[i] << 24) | (msg[i+1] << 16) | (msg[i+2] << 8) | msg[i+3];
                word_array.push(j);
            }
         
            // Push bit 1
            switch (msg_len % 4) {
                case 0:
                    i = 0x080000000;
                    break;
                case 1:
                    i = (msg[msg_len-1] << 24) | 0x0800000;
                    break;
                case 2:
                    i = (msg[msg_len-2] << 24) | (msg[msg_len-1] << 16) | 0x08000;
                    break;
                case 3:
                    i = (msg[msg_len-3] << 24) | (msg[msg_len-2] << 16) | (msg[msg_len-1] << 8) | 0x80;
                    break;
            }
            word_array.push(i);
    
            // Fill to minimum length
            while ((word_array.length % 16) != 14)
                word_array.push(0);
         
            // Push message length
            word_array.push(msg_len >>> 29);
            word_array.push((msg_len << 3) & 0x0ffffffff);
         
            // Block
            for (blockstart=0; blockstart < word_array.length; blockstart += 16) {
         
                for (i=0; i<16; i++) W[i] = word_array[blockstart+i];
                for (i=16; i<=79; i++) W[i] = rol32(W[i-3] ^ W[i-8] ^ W[i-14] ^ W[i-16], 1);
         
                A = H0;
                B = H1;
                C = H2;
                D = H3;
                E = H4;
         
                for ( i= 0; i<=19; i++ ) {
                    temp = (rol32(A,5) + ((B&C) | (~B&D)) + E + W[i] + 0x5A827999) & 0x0ffffffff;
                    E = D;
                    D = C;
                    C = rol32(B,30);
                    B = A;
                    A = temp;
                }
         
                for ( i=20; i<=39; i++ ) {
                    temp = (rol32(A,5) + (B ^ C ^ D) + E + W[i] + 0x6ED9EBA1) & 0x0ffffffff;
                    E = D;
                    D = C;
                    C = rol32(B,30);
                    B = A;
                    A = temp;
                }
         
                for ( i=40; i<=59; i++ ) {
                    temp = (rol32(A,5) + ((B&C) | (B&D) | (C&D)) + E + W[i] + 0x8F1BBCDC) & 0x0ffffffff;
                    E = D;
                    D = C;
                    C = rol32(B,30);
                    B = A;
                    A = temp;
                }
         
                for ( i=60; i<=79; i++ ) {
                    temp = (rol32(A,5) + (B ^ C ^ D) + E + W[i] + 0xCA62C1D6) & 0x0ffffffff;
                    E = D;
                    D = C;
                    C = rol32(B,30);
                    B = A;
                    A = temp;
                }
         
                H0 = (H0 + A) & 0x0ffffffff;
                H1 = (H1 + B) & 0x0ffffffff;
                H2 = (H2 + C) & 0x0ffffffff;
                H3 = (H3 + D) & 0x0ffffffff;
                H4 = (H4 + E) & 0x0ffffffff;
         
            }

            // Integer to byte array
            function int2arr(arr, val) {
                var i;
                for (i=3; i>=0; i--) {
                    var v = ((val >>> (i*8)) & 0xff);
                    arr.push(v);
                }
            };
    
            // Result array
            var res = new Array();
            int2arr(res, H0);
            int2arr(res, H1);
            int2arr(res, H2);
            int2arr(res, H3);
            int2arr(res, H4);
            return res;
         
        }
        function js_arr_print(arr) {
            var i;
            var str = "";
            for (i=0; i<arr.length; i++) {
                var v = arr[i].toString(16);
                while (v.length < 2)
                    v = "0" + v;
                while (v.length > 2)
                    v = v.substr(1);
                str += v;
            }
            return str;
        }
        function js_arr_str(str) {
            var arr = new Array();
            var i;
            for (i=0; i<str.length; i++)
                arr.push(str.charCodeAt(i) & 0xff);
            return arr;
        }
        function js_arr_xor(a, b) {
            var i;
            for (i=0; i<a.length; i++)
                a[i] ^= b[i];
            return a;
        }
        function js_arr_b64(arr) {
            var b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz012345678901=";
            var r = "";
            var i;
            var size = arr.length;
            while (size % 3 != 0)
                size--;
            for (i=0; i<size; i += 3) {
                var j;
                var v = 0;
                for (j=0; j<3; j++)
                    v = (v << 8) | arr[i + (2 - j)];
                for (j=0; j<4; j++) {
                    var t = (v & 0x3f);
                    v = (v >>> 6);
                    r += b64[t];
                }
            }
            return r;
        }
        function js_hash() {
            var v_target = document.getElementById("hash_target").value;
            var v_master = document.getElementById("hash_master").value;
            var v_sha = js_sha1(js_arr_xor(js_sha1(js_arr_str(v_master)), js_sha1(js_arr_str(v_target))));
            document.getElementById("hash_hash").value = js_arr_b64(v_sha).substr(0, 12);    
        }
    //]]></script>

</head>
<body>

    <div id="title">ひみつ</div>
    <div id="main">
        <form id="hash_form" action="?" method="post">
            <fieldset>
                <label for="hash_target">Target</label><br />
                <input type="text" id="hash_target" name="target" value="<?php echo $hash_target; ?>" size="24" onkeyup="js_hash();" /><br />
                <label for="hash_master">Master</label><br />
                <input type="password" id="hash_master" name="master" value="<?php echo $hash_master; ?>" size="24" onkeyup="js_hash();" /><br />
                <label for="hash_hash">Hash</label><br />
                <input type="text" id="hash_hash" value="<?php echo $hash_hash; ?>" size="24" readonly="readonly" /><br />
            </fieldset>
            <noscript>
                <fieldset>
                    <br /><button name="action" value="send" type="submit">Calculate</button>
                </fieldset>
            </noscript>
        </form>
    </div>

</body>
</html>

