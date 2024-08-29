rule lockton_linux
{
    meta:
        author = "Pir00t"
        description = "Detects Lockton ELF ransomware based on specific IoCs including ransom note and potential hardcoded encryption key."
        date = "2024-08-29"
        reference = "https://ultimacybr.co.uk/2024-08-29-Lockton/"
        hash = "cf37b3caea9b8f6bf3297f2d9c562703ad0eb4f6a27df9b105bd7c9aa9ca95ee"
        hash2 = "1a1fb87d76abf41ca90a476ff1aa6d6883db0a8848eba839b6b3826d19523a77"

    strings:
        $s = "Lockton Ransomware" ascii
        $s1 = "Your files have been encrypted. To recover them, please follow the instructions below. DO NOT CLOSE THIS WINDOW OR POWER OFF YOUR DEVICE!" ascii
        $s2 = "IF YOU DO SO YOU WILL BE UNABLE TO RECOVER YOUR FILES!" ascii
        $s3 = "Download the official Monero wallet from getmonero.org" ascii
        $s4 = "Purchase [INSERT AMOUNT OF USD] worth of Monero and send it to the following Monero address:" ascii
        $s5 = "After sending the payment, download Dino XMPP and send the ransom payment transaction ID to the following XMPP" ascii
        $s6 = "Use the decryption key to recover your encrypted files below" ascii
        
        $static_path = "/home" ascii
        $static_key = "1BD0B3CFB4FCB84DEA46826619880D255037BFB6996E3EAF44FA49D831D7B33D" ascii
        $static_logfile = "encryptedfiles.txt" ascii

    condition:
        uint32(0) == 0x464c457f and
        (
            any of ($static_path, $static_key, $static_logfile) and
            all of ($s*)
        )
}
