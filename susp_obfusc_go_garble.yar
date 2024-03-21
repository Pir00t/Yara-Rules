rule susp_obfusc_go_garble
{
    meta:
        author = "Pir00t"
        description = "Detect Go binaries (cross platform) that may have been obfuscated using the garble tool"
        tool_ref = "https://github.com/burrowers/garble"
        date = "2024-03-18"
        hash1 = "2c03c810c9e05a3d44fc6e16a99f4ee561d092740c4ad85640e8482e78cd1a7c"
        hash2 = "5d059f31b7b57988f3518b6b95ea7ca1556da482c682672a43b82232b8cd4a07"
        hash3 = "17ddde127824ad8eaf39ae76ef2137b0208959e7900a962d6bca1b6c3c375c39"
        hash4 = "ab6403423518f79d36c8c4ffd62d6396df3d0f01602c90cf6e0b01889baaba31"
        hash5 = "d06c9dc26920dea808eb829962eb0206a9db7b2898ede9291d2a957c5dc66fc5"
        hash6 = "b8c798a21d090df134e3efa71a08c84f1bd458df442ac08f288138d530555881"


    strings:
        $a1 = "go.build"
        $a2 = "Go build"

        $s1 = "runtime"
        $s2 = "reflect"
        $s3 = "embed"
        $s4 = "sync"

        $x1 = /\w{6,11}_\./

    condition:
        1 of ($a*) 
        and 2 of ($s*)
        and $x1
}