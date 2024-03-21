rule hktl_implant_havoc_custom_agent
{
    meta:
        author = "Pir00t"
        description = "Attempt to detect custom, 3rd party agents built to communicate with the Havoc C2 API"
        tool_ref = "https://github.com/HavocFramework/Havoc"
        havoc_agent_params = "https://github.com/HavocFramework/Talon/blob/main/Agent/Talon.py"
        date = "2024-03-14"
        hash = "822fca5e50512c781066712acc121a0e155fab2499019dd551f0053592aad65d"
        hash2 = "c19eaa5050581454e2c3d922cf6e3b884c86af94f21c18f38b307c5b05726630"
        hash3 = "f604c95ea22d626b26a9363c552e50462b3d2fcb84494cfe54cf942eda944d13"


    strings:
        $havoc1 = "AgentID"
        $havoc2 = "Hostname"
        $havoc3 = "Username"
        $havoc4 = "Domain"
        $havoc5 = "InternalIP"
        $havoc6 = "Process Path"
        $havoc7 = "Process ID"
        $havoc8 = "Process Parent ID"
        $havoc9 = "Process Arch"
        $havoc10 = "Process Elevated"
        $havoc11 = "OS Build"
        $havoc12 = "OS Arch"
        $havoc13 = "Sleep"
        $havoc14 = "Process Name"
        $havoc15 = "OS Version"

    condition:
        10 of them
}