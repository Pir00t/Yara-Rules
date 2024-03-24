rule upx_elf
{
	meta:
		author = "Pir00t"
        description = "Detect ELF files packed with vanilla UPX"
        tool_ref = "https://github.com/upx/upx"
        date = "2024-03-24"

	strings:
		$s1 = "UPX!"
		$s2 = "UPX executable packer"

	condition:
		(uint32(0) == 0x464c457f) and all of them		
}

rule upx_pe
{
    meta:
		author = "Pir00t"
        description = "Detect PE files packed with vanilla UPX"
        tool_ref = "https://github.com/upx/upx"
        date = "2024-03-24"

	strings:
		$s1 = { 55 50 58 30 00 00 00}
		$s2 = { 55 50 58 31 00 00 00}
		$s3 = { 55 50 58 32 00 00 00}
		$s4 = "UPX!"

	condition:
		(uint16(0) == 0x5a4d) and all of them
}