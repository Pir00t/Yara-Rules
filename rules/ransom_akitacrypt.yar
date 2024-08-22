rule akitacrypt_linux
{
    meta:
        author = "Pir00t"
        description = "Detects AkitaCrypt ELF ransomware based on specific IoCs including Bitcoin address, threat actor email, and ransom note."
        date = "2024-08-22"
        reference = "https://ultimacybr.co.uk/2024-08-22-AkitaCrypt/"
        hash = "e648b3f73b75ca27ca5eb07dbcd1f00779bd49d81d3bf0c043dd8eb695fe4e95"

    strings:
        $bitcoin_address = "bc1qhs5rqstmq6pax043h5ek4u8pwgct5l7kya6uq6"
        $ta_email = "getmyfilesbacknow@protonmail.com"
        $ransom_note_image_url = "i.ibb.co/NZvXnDP/akita.png"
        $s = "Team Akita" ascii
        $s1 = "Any delay past 24 hours will be met with an additional 0.025 BTC increase in the ransom amount per day." ascii
        $s2 = "After we receive 3 confirmations of payment on the blockchain" ascii
        $s3 = "Your time ends at" ascii

    condition:
        uint32(0) == 0x464c457f and
        (
            any of ($bitcoin_address, $threat_actor_email, $ransom_note_image_url) and
            all of ($s*)
        )
}
