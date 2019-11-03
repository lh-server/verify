# Light's Hope Export Verifier
This project contains a C++ example implementation of a Light's Hope character data verifier. When provided with the contents of 
an exported account data archive, it can ensure that the data has not been tampered with since being exported from the Light's Hope website.
To achieve this, it uses ECDSA (Elliptic Curve Digital Signature Algorithm) to generate a signature using an asymmetric key pair that can
then be verified by the end-user to ensure no tampering has taken place. This is the same fundamental technique used to sign cryptocurrency
transactions.

Although intended as an example of how to verify exported characters, you may wish to simply invoke this application as part of your 
importing pipeline.

### File contents
Each account is exported as a zip archive containing three files; account.json, key and signature.

* `characters.json` contains character data encompassing Northdale, Lightbringer and Silver Hand.
* `pubkey` contains the public key that can be used in conjunction with the signature to verify whether `characters.json` has been 
modified since export. This file is provided only to assist in in the event of key revokation. Under no circumstances should it be used 
to verify whether the data is from Light's Hope. A malicious user could replace this key and signature with their own - use only the 
key from the Light's Hope website. This example implementation will not accept an ASCII-encoded `pubkey` without modification.
* `signature` contains the cryptographic signature for `characters.json`.

### Building
Building this project requires CMake, the Botan cryptographic library and a recent version of Clang, GCC or Visual Studio 2019.
Botan is available as a package on most Linux distributions.

### Running
>Precautions:
As mentioned above, the public key included within the data archive should not be used to verify whether the data is from Light's Hope. 
Only use the public key provided on the Light's Hope website.

To use the application, simply provide three arguments; `-pubkey`, `-json` and `-signature`. `-json` is the provided `characters.json`, 
`pubkey` is the public key available from the Light's Hope website or this repository (see the root) and `-signature` is expected 
cryptographic signature, provided directly on the command line rather than as a file. By default, `-signature` expects a decimal value so prepend
`0x` when providing a hexadecimal value.

If verification succeeds, the application will print `Signature OK`, or `Signature Invalid` on failure. A return code of `0` indicates success,
whereas `1` indicates a failed verification. Any other value indicates that an error occured - see `stderr`.

>Note: You can optionally omit the `-json` argument and instead pipe the file to the application through stdin.

### Importing

The provided `characters.json` contains information on every character contained on a Light's Hope account. No
account data is provided aside from an account ID. Usernames, password data, email addresses, ban/warning notes
are not included. Permanently banned accounts are not available for export.

| Table |  Description|
|-------|-----------|
| character_action |     Describes a character's action bar layout, mapping skills/macros/items to slots/binds. |
| character_aura   |     Describes any active character auras (e.g. buffs).     |
| character_gifts   |    Describes any gift-wrapped items the character holds.     |
| character_homebind   | Contains the character's hearthstone location.         |
| character_inventory   |     Contains details on a character's inventory.     |
| character_pet   |     Describes any pets the character owns.     |
| character_queststatus   |     Describes a character's quest progress, including reward selection.     |
| character_reputation   |     Describes a character's standing with any discovered factions.     |
| character_skills   |     Describes a character's learned skills.     |
| character_spell   |     Describes a character's learned speells.     |
| character_spell_cooldown   |     Contains information on any items/spells that are on cooldown.     |
| character_stats   |     Describes a character's stats (e.g. health, mana).     |
| characters   |     Describes the base data for a character (e.g. location, class, faction).     |
| merge_char_data   |    Contains the provenance of a character that was transferred during the Anathema & Darrowshire to Lightbringer merge.   |
| item_instance   |     Describes items owned by the character, including those that were on the auction house or in their mailbox.     |

The MaNGOS wiki can provided detailed information on the function of each table and its columns. Some tables will contain data that is specific to
the core used by Light's Hope. It is up to each importing project whether they decide to make use of this additional data in their core.

### Realm history
Every realm launched during the timeline shown in the diagram below was a progressive server starting on patch 1.2, with the exception 
of Silver Hand. All servers ran with 1x experience and drop rates, aiming for close approximation of the original experienced offered 
back in 2004 to 2006.

#### Lightbringer (PvP)
The oldest and largest of the realms. Lightbringer is an amalgamation of three individual realms; Anathema (previously Nostalrius PvP), Elysium PvP and Darrowshire (previously Nostalrius PvE).

#### Northdale (PvP)
Launched several months after the the project's inception, Northdale followed in the footsteps of previous progressive realms after Lightbringer reached patch 1.12.

#### Silver Hand (PvP)
A short-term, non-progressive, 1.12 realm catering to casual players seeking Classic prepration, hardcore players looking to practice their speed-leveling strategies and those interested in pushing themselves to clear as much content as possible within a short window of time. Following progression on Silver Hand made it seem likely that a dedicated guild could feasibly clear all PvE content within 4-6 weeks of a realm's launch, excluding the war effort's public resource gathering phase but including commendation.

This ASCII diagram shows the relationship between each realm.

```
 ========================= Nostalrius =============================

      Nostalrius Begins
              |
       Nostalrius PvP   Nostalrius PvE
              x                x
====================== Elysium Project =============================
              |                |
 Valkyrie-----v                |                                
           Anathema       Darrowshire
               |               |              Elysium PvP
               |               |                  |           Zeth'Kur
               |               |                  |               |
               v---------------v------------------v-------------- <
               |               |                  |
               |               |                  |
17/10/2017 ============= Light's Hope =============================
               |               |                  | 
           Anathema       Darrowshire        Lightbringer
               |               |                  |             
23/06/2018     |               |                  |         Northdale      
22/06/2019     >--------------->------------------v             |         Silver Hand
                                                  |             |              |
25/08/2019                                        x             x              x
```

