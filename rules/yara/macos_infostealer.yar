/*
 * ZAAFVesper - macOS infostealer harvesting logic.
 * Original rule written for ZAAFVesper; no strings copied from public rule sets.
 * Logic: a Mach-O (thin or universal) or script that references the keychain
 * AND several browser credential stores AND crypto-wallet locations. Each group
 * alone is common (browsers, password managers, backup tools); all three
 * together in one small binary is the shape of AMOS/Atomic, Banshee, Cuckoo
 * and Poseidon-style stealers.
 */

rule MAL_Mac_Infostealer_HarvestTargets_Nov26 : stealer macos
{
    meta:
        author = "ZAAFVesper"
        description = "Detects macOS infostealers that bundle keychain, browser credential store and crypto wallet target paths in one binary or script"
        reference = "https://attack.mitre.org/techniques/T1555/"
        attack = "T1555.003"
        date = "2026-11-07"
        scope = "endpoint scanning (exec + watched downloads)"

    strings:
        $kc1 = "login.keychain-db" ascii
        $kc2 = "Library/Keychains/" ascii
        $kc3 = "Safe Storage" ascii

        $br1 = "Google/Chrome/" ascii
        $br2 = "BraveSoftware/Brave-Browser" ascii
        $br3 = "Microsoft Edge/" ascii
        $br4 = "com.operasoftware.Opera" ascii
        $br5 = "Firefox/Profiles" ascii
        $br6 = "Cookies.binarycookies" ascii
        $br7 = "Login Data" ascii

        $wl1 = "Exodus/exodus.wallet" ascii
        $wl2 = "Electrum/wallets" ascii
        $wl3 = "atomic/Local Storage/leveldb" ascii
        $wl4 = "Ledger Live" ascii
        $wl5 = "nkbihfbeogaeaoehlefnkodbefgpgknn" ascii   // MetaMask extension ID
        $wl6 = "bfnaelmomeimhlpmgjnjophhpkkoljpa" ascii   // Phantom extension ID
        $wl7 = "Coinomi/wallets" ascii

    condition:
        filesize < 30MB
        and (uint32(0) == 0xfeedfacf or uint32(0) == 0xfeedface or uint32be(0) == 0xcafebabe or uint16(0) == 0x2123)
        and any of ($kc*)
        and 3 of ($br*)
        and 2 of ($wl*)
}
