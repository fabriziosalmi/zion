# The README hero screenshot, as a reproducible recipe (rendered by `vhs`).
# Driven by scripts/update-readme-boot-shot.sh, which builds the release
# binary and prepares /tmp/zion-boot-shot (config + throwaway self-signed
# cert) before invoking vhs. Do not run this tape directly.
Output "/tmp/zion-boot-shot/boot.gif"
Set Width 1220
Set Height 1040
Set FontSize 15
Set Padding 20
Type "ZION_CONFIG=/tmp/zion-boot-shot/zion.toml ./target/release/zion"
Enter
Sleep 6s
Screenshot "docs/img/boot.png"
