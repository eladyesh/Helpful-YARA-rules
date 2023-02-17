import "pe"

rule open_for_c
{
    strings:
        $filename = "path"
        $open_call = /(File\.Open(Read|Write|)|new FileStream)\(\s*[^"]*["']\s*[^\)]*\)/
        $write_call = /(File\.Write|fs\.Write)\(/

    condition:
        any of ($*)
}
