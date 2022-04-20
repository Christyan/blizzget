# blizzget

[Download](https://github.com/d07RiV/blizzget/releases)

Blizzard CDN downloader. Capable of downloading upcoming versions of games. **They will most likely not be playable, but can be used for datamining and such** - if you're going to try to play the game, make sure you run it through battle.net app so it can fix the possible inconsistencies. Note that it always stores the CASC archive in the /Data folder, which is not correct for every game - you might want to rename the folder to what the actual game uses. Currently I only tested it for Diablo III.

The program represents a simple 4-step wizard.

Step 1: select game and region.  
Step 2: select build version.  
Step 3: select a combination of download tags - these are used to specify the platform, language, etc.  
Step 4: select download location and start the download.

Note that the program creates a cache in its local directory, which significantly increases disk usage (doubles or even triples, because it often loads partial archives and reserves space for the entire file), but re-downloading the game, or downloading future versions can take significantly less time. You can delete the cache folder after downloading if you value disk space over future network traffic.

Using this is not recommended for playable versions, as it is probably slower than the battle.net launcher (due to only using one download thread), and might not install everything correctly. It is also incapable of patching (aka upgrading a previous installation). You might be able to use it to pre-download an upcoming game and then use the battle.net launcher to 'fix' it (make sure to rename the Data folder to what is appropriate for the specific game, though.. in some cases it even has to be inside another folder, i.e. /data/casc for Overwatch).


<hr/>

<b>Overwatch Beta</b>
1. Download an pre built app, on releases tab (or compile yourself with VS2022)
2. Open app and select program code: "prob - Overwatch Beta" and region you want.
3. Select only available build id that exists, must be like: `build-branch = 2_00_8_0`
4. Wait untill encoding table is fetched and download list is prepared.
5. Select language you want.
6. Select destination folder to download files then click Start
7. Wait for download complete and be happy with files because you cannot login since your account must be allowed to join in server 😂